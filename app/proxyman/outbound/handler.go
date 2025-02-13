package outbound

import (
	"context"
	"crypto/rand"
	goerrors "errors"
	"io"
	"math/big"
	gonet "net"
	"os"

	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/mux"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/net/cnc"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
	"github.com/xtls/xray-core/transport/pipe"
)

func getStatCounter(v *core.Instance, tag string) (stats.Counter, stats.Counter) {
	var uplinkCounter stats.Counter
	var downlinkCounter stats.Counter

	policy := v.GetFeature(policy.ManagerType()).(policy.Manager)
	if len(tag) > 0 && policy.ForSystem().Stats.OutboundUplink {
		statsManager := v.GetFeature(stats.ManagerType()).(stats.Manager)
		name := "outbound>>>" + tag + ">>>traffic>>>uplink"
		c, _ := stats.GetOrRegisterCounter(statsManager, name)
		if c != nil {
			uplinkCounter = c
		}
	}
	if len(tag) > 0 && policy.ForSystem().Stats.OutboundDownlink {
		statsManager := v.GetFeature(stats.ManagerType()).(stats.Manager)
		name := "outbound>>>" + tag + ">>>traffic>>>downlink"
		c, _ := stats.GetOrRegisterCounter(statsManager, name)
		if c != nil {
			downlinkCounter = c
		}
	}

	return uplinkCounter, downlinkCounter
}

// Handler implements outbound.Handler.
type Handler struct {
	tag             string
	senderSettings  *proxyman.SenderConfig
	streamSettings  *internet.MemoryStreamConfig
	proxy           proxy.Outbound
	outboundManager outbound.Manager
	mux             *mux.ClientManager
	xudp            *mux.ClientManager
	udp443          string
	uplinkCounter   stats.Counter
	downlinkCounter stats.Counter
}

// NewHandler creates a new Handler based on the given configuration.
func NewHandler(ctx context.Context, config *core.OutboundHandlerConfig) (outbound.Handler, error) {
	v := core.MustFromContext(ctx)
	uplinkCounter, downlinkCounter := getStatCounter(v, config.Tag)
	h := &Handler{
		tag:             config.Tag,
		outboundManager: v.GetFeature(outbound.ManagerType()).(outbound.Manager),
		uplinkCounter:   uplinkCounter,
		downlinkCounter: downlinkCounter,
	}

	if config.SenderSettings != nil {
		senderSettings, err := config.SenderSettings.GetInstance()
		if err != nil {
			return nil, err
		}
		switch s := senderSettings.(type) {
		case *proxyman.SenderConfig:
			h.senderSettings = s
			mss, err := internet.ToMemoryStreamConfig(s.StreamSettings)
			if err != nil {
				return nil, errors.New("failed to parse stream settings").Base(err).AtWarning()
			}
			h.streamSettings = mss
		default:
			return nil, errors.New("settings is not SenderConfig")
		}
	}

	proxyConfig, err := config.ProxySettings.GetInstance()
	if err != nil {
		return nil, err
	}

	rawProxyHandler, err := common.CreateObject(ctx, proxyConfig)
	if err != nil {
		return nil, err
	}

	proxyHandler, ok := rawProxyHandler.(proxy.Outbound)
	if !ok {
		return nil, errors.New("not an outbound handler")
	}

	if h.senderSettings != nil && h.senderSettings.MultiplexSettings != nil {
		if config := h.senderSettings.MultiplexSettings; config.Enabled {
			if config.Concurrency < 0 {
				h.mux = &mux.ClientManager{Enabled: false}
			}
			if config.Concurrency == 0 {
				config.Concurrency = 8 // same as before
			}
			if config.Concurrency > 0 {
				h.mux = &mux.ClientManager{
					Enabled: true,
					Picker: &mux.IncrementalWorkerPicker{
						Factory: &mux.DialingWorkerFactory{
							Proxy:  proxyHandler,
							Dialer: h,
							Strategy: mux.ClientStrategy{
								MaxConcurrency: uint32(config.Concurrency),
								MaxConnection:  128,
							},
						},
					},
				}
			}
			if config.XudpConcurrency < 0 {
				h.xudp = &mux.ClientManager{Enabled: false}
			}
			if config.XudpConcurrency == 0 {
				h.xudp = nil // same as before
			}
			if config.XudpConcurrency > 0 {
				h.xudp = &mux.ClientManager{
					Enabled: true,
					Picker: &mux.IncrementalWorkerPicker{
						Factory: &mux.DialingWorkerFactory{
							Proxy:  proxyHandler,
							Dialer: h,
							Strategy: mux.ClientStrategy{
								MaxConcurrency: uint32(config.XudpConcurrency),
								MaxConnection:  128,
							},
						},
					},
				}
			}
			h.udp443 = config.XudpProxyUDP443
		}
	}

	h.proxy = proxyHandler
	return h, nil
}

// Tag implements outbound.Handler.
func (h *Handler) Tag() string {
	return h.tag
}

// Dispatch implements proxy.Outbound.Dispatch.
func (h *Handler) Dispatch(ctx context.Context, link *transport.Link) {
	outbounds := session.OutboundsFromContext(ctx)
	ob := outbounds[len(outbounds)-1]
	if ob.Target.Network == net.Network_UDP && ob.OriginalTarget.Address != nil && ob.OriginalTarget.Address != ob.Target.Address {
		link.Reader = &buf.EndpointOverrideReader{Reader: link.Reader, Dest: ob.Target.Address, OriginalDest: ob.OriginalTarget.Address}
		link.Writer = &buf.EndpointOverrideWriter{Writer: link.Writer, Dest: ob.Target.Address, OriginalDest: ob.OriginalTarget.Address}
	}
	if h.mux != nil {
		test := func(err error) {
			if err != nil {
				err := errors.New("failed to process mux outbound traffic").Base(err)
				session.SubmitOutboundErrorToOriginator(ctx, err)
				errors.LogInfo(ctx, err.Error())
				common.Interrupt(link.Writer)
			}
		}
		if ob.Target.Network == net.Network_UDP && ob.Target.Port == 443 {
			switch h.udp443 {
			case "reject":
				test(errors.New("XUDP rejected UDP/443 traffic").AtInfo())
				return
			case "skip":
				goto out
			}
		}
		if h.xudp != nil && ob.Target.Network == net.Network_UDP {
			if !h.xudp.Enabled {
				goto out
			}
			test(h.xudp.Dispatch(ctx, link))
			return
		}
		if h.mux.Enabled {
			test(h.mux.Dispatch(ctx, link))
			return
		}
	}
out:
	err := h.proxy.Process(ctx, link, h)
	if err != nil {
		if goerrors.Is(err, io.EOF) || goerrors.Is(err, io.ErrClosedPipe) || goerrors.Is(err, context.Canceled) {
			err = nil
		}
	}
	if err != nil {
		// Ensure outbound ray is properly closed.
		err := errors.New("failed to process outbound traffic").Base(err)
		session.SubmitOutboundErrorToOriginator(ctx, err)
		errors.LogInfo(ctx, err.Error())
		common.Interrupt(link.Writer)
	} else {
		common.Close(link.Writer)
	}
	common.Interrupt(link.Reader)
}

// Address implements internet.Dialer.
func (h *Handler) Address() net.Address {
	if h.senderSettings == nil || h.senderSettings.Via == nil {
		return nil
	}
	return h.senderSettings.Via.AsAddress()
}

func (h *Handler) DestIpAddress() net.IP {
	return internet.DestIpAddress()
}

// Dial implements internet.Dialer.
func (h *Handler) Dial(ctx context.Context, dest net.Destination) (stat.Connection, error) {
	if h.senderSettings != nil {
		if h.senderSettings.ProxySettings.HasTag() {
			tag := h.senderSettings.ProxySettings.Tag
			handler := h.outboundManager.GetHandler(tag)
			if handler != nil {
				errors.LogDebug(ctx, "proxying to ", tag, " for dest ", dest)
				outbounds := session.OutboundsFromContext(ctx)
				ctx = session.ContextWithOutbounds(ctx, append(outbounds, &session.Outbound{
					Target: dest,
					Tag:    tag,
				})) // add another outbound in session ctx
				opts := pipe.OptionsFromContext(ctx)
				uplinkReader, uplinkWriter := pipe.New(opts...)
				downlinkReader, downlinkWriter := pipe.New(opts...)

				go handler.Dispatch(ctx, &transport.Link{Reader: uplinkReader, Writer: downlinkWriter})
				conn := cnc.NewConnection(cnc.ConnectionInputMulti(uplinkWriter), cnc.ConnectionOutputMulti(downlinkReader))

				if config := tls.ConfigFromStreamSettings(h.streamSettings); config != nil {
					tlsConfig := config.GetTLSConfig(tls.WithDestination(dest))
					conn = tls.Client(conn, tlsConfig)
				}

				return h.getStatCouterConnection(conn), nil
			}

			errors.LogWarning(ctx, "failed to get outbound handler with tag: ", tag)
		}

		if h.senderSettings.Via != nil {
			outbounds := session.OutboundsFromContext(ctx)
			ob := outbounds[len(outbounds)-1]
			if h.senderSettings.ViaCidr == "" {
				if h.senderSettings.Via.AsAddress().Family().IsDomain() && h.senderSettings.Via.AsAddress().Domain() == "origin" {
					if inbound := session.InboundFromContext(ctx); inbound != nil {
						origin, _, err := net.SplitHostPort(inbound.Conn.LocalAddr().String())
						if err == nil {
							ob.Gateway = net.ParseAddress(origin)
						}
					}
				} else {
					ob.Gateway = h.senderSettings.Via.AsAddress()
				}
			} else { //Get a random address.
				ob.Gateway = ParseRandomIPv6(h.senderSettings.Via.AsAddress(), h.senderSettings.ViaCidr)
			}
		}
	}

	if conn, err := h.getUoTConnection(ctx, dest); err != os.ErrInvalid {
		return conn, err
	}

	conn, err := internet.Dial(ctx, dest, h.streamSettings)
	conn = h.getStatCouterConnection(conn)
	outbounds := session.OutboundsFromContext(ctx)
	ob := outbounds[len(outbounds)-1]
	ob.Conn = conn
	return conn, err
}

func (h *Handler) getStatCouterConnection(conn stat.Connection) stat.Connection {
	if h.uplinkCounter != nil || h.downlinkCounter != nil {
		return &stat.CounterConnection{
			Connection:   conn,
			ReadCounter:  h.downlinkCounter,
			WriteCounter: h.uplinkCounter,
		}
	}
	return conn
}

// GetOutbound implements proxy.GetOutbound.
func (h *Handler) GetOutbound() proxy.Outbound {
	return h.proxy
}

// Start implements common.Runnable.
func (h *Handler) Start() error {
	return nil
}

// Close implements common.Closable.
func (h *Handler) Close() error {
	common.Close(h.mux)
	return nil
}

func ParseRandomIPv6(address net.Address, prefix string) net.Address {
	_, network, _ := gonet.ParseCIDR(address.IP().String() + "/" + prefix)

	maskSize, totalBits := network.Mask.Size()
	subnetSize := big.NewInt(1).Lsh(big.NewInt(1), uint(totalBits-maskSize))

	// random
	randomBigInt, _ := rand.Int(rand.Reader, subnetSize)

	startIPBigInt := big.NewInt(0).SetBytes(network.IP.To16())
	randomIPBigInt := big.NewInt(0).Add(startIPBigInt, randomBigInt)

	randomIPBytes := randomIPBigInt.Bytes()
	randomIPBytes = append(make([]byte, 16-len(randomIPBytes)), randomIPBytes...)

	return net.ParseAddress(gonet.IP(randomIPBytes).String())
}
