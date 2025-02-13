package splithttp

import (
	"context"
	gotls "crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/signal/done"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/browser_dialer"
	"github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
	"github.com/xtls/xray-core/transport/pipe"
	"golang.org/x/net/http2"
)

// defines the maximum time an idle TCP session can survive in the tunnel, so
// it should be consistent across HTTP versions and with other transports.
const connIdleTimeout = 300 * time.Second

// consistent with quic-go
const quicgoH3KeepAlivePeriod = 10 * time.Second

// consistent with chrome
const chromeH2KeepAlivePeriod = 45 * time.Second

type dialerConf struct {
	net.Destination
	*internet.MemoryStreamConfig
}

var (
	globalDialerMap    map[dialerConf]*XmuxManager
	globalDialerAccess sync.Mutex
)

func getHTTPClient(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) (DialerClient, *XmuxClient) {
	realityConfig := reality.ConfigFromStreamSettings(streamSettings)

	if browser_dialer.HasBrowserDialer() && realityConfig == nil {
		return &BrowserDialerClient{transportConfig: streamSettings.ProtocolSettings.(*Config)}, nil
	}

	globalDialerAccess.Lock()
	defer globalDialerAccess.Unlock()

	if globalDialerMap == nil {
		globalDialerMap = make(map[dialerConf]*XmuxManager)
	}

	key := dialerConf{dest, streamSettings}

	xmuxManager, found := globalDialerMap[key]

	if !found {
		transportConfig := streamSettings.ProtocolSettings.(*Config)
		var xmuxConfig XmuxConfig
		if transportConfig.Xmux != nil {
			xmuxConfig = *transportConfig.Xmux
		}

		xmuxManager = NewXmuxManager(xmuxConfig, func() XmuxConn {
			return createHTTPClient(dest, streamSettings)
		})
		globalDialerMap[key] = xmuxManager
	}

	xmuxClient := xmuxManager.GetXmuxClient(ctx)
	return xmuxClient.XmuxConn.(DialerClient), xmuxClient
}

func decideHTTPVersion(tlsConfig *tls.Config, realityConfig *reality.Config) string {
	if realityConfig != nil {
		return "2"
	}
	if tlsConfig == nil {
		return "1.1"
	}
	if len(tlsConfig.NextProtocol) != 1 {
		if slices.Contains(tlsConfig.NextProtocol, "h3") && slices.Contains(tlsConfig.NextProtocol, "h2") {
			return "3+2"
		}
		return "2"
	}
	if tlsConfig.NextProtocol[0] == "http/1.1" {
		return "1.1"
	}
	if tlsConfig.NextProtocol[0] == "h3" {
		return "3"
	}

	return "2"
}

func createHTTPClient(dest net.Destination, streamSettings *internet.MemoryStreamConfig) DialerClient {
	tlsConfig := tls.ConfigFromStreamSettings(streamSettings)
	realityConfig := reality.ConfigFromStreamSettings(streamSettings)

	httpVersion := decideHTTPVersion(tlsConfig, realityConfig)

	var gotlsConfig *gotls.Config
	var h3gotlsConfig *gotls.Config

	if tlsConfig != nil {
		gotlsConfig = tlsConfig.GetTLSConfig(tls.WithDestination(dest))
		h3gotlsConfig = gotlsConfig

		if httpVersion == "3+2" {
			h3gotlsConfig = &gotls.Config{}
			*h3gotlsConfig = *gotlsConfig

			// Make QUIC ALPN only contains h3, and remove h3 from TCP TLS ALPN
			h3gotlsConfig.NextProtos = []string{"h3"}
			h3idx := slices.Index(h3gotlsConfig.NextProtos, "h3")
			// Don't modify original tlsConfig.NextProtocol
			nextProtos := gotlsConfig.NextProtos
			gotlsConfig.NextProtos = make([]string, 0, len(nextProtos)-1)
			gotlsConfig.NextProtos = append(gotlsConfig.NextProtos, nextProtos[:h3idx]...)
			gotlsConfig.NextProtos = append(gotlsConfig.NextProtos, nextProtos[h3idx+1:]...)
		}
	}

	transportConfig := streamSettings.ProtocolSettings.(*Config)

	dialContext := func(ctxInner context.Context) (net.Conn, error) {
		conn, err := internet.DialSystem(ctxInner, dest, streamSettings.SocketSettings)
		if err != nil {
			return nil, err
		}

		if realityConfig != nil {
			return reality.UClient(conn, realityConfig, ctxInner, dest)
		}

		if gotlsConfig != nil {
			if fingerprint := tls.GetFingerprint(tlsConfig.Fingerprint); fingerprint != nil {
				conn = tls.UClient(conn, gotlsConfig, fingerprint)
				if err := conn.(*tls.UConn).HandshakeContext(ctxInner); err != nil {
					return nil, err
				}
			} else {
				conn = tls.Client(conn, gotlsConfig)
			}
		}

		return conn, nil
	}

	var keepAlivePeriod time.Duration
	if streamSettings.ProtocolSettings.(*Config).Xmux != nil {
		keepAlivePeriod = time.Duration(streamSettings.ProtocolSettings.(*Config).Xmux.HKeepAlivePeriod) * time.Second
	}

	var transport http.RoundTripper

	makeH3Transport := func() *http3.Transport {
		if keepAlivePeriod == 0 {
			keepAlivePeriod = quicgoH3KeepAlivePeriod
		}
		if keepAlivePeriod < 0 {
			keepAlivePeriod = 0
		}
		quicConfig := &quic.Config{
			MaxIdleTimeout: connIdleTimeout,

			// these two are defaults of quic-go/http3. the default of quic-go (no
			// http3) is different, so it is hardcoded here for clarity.
			// https://github.com/quic-go/quic-go/blob/b8ea5c798155950fb5bbfdd06cad1939c9355878/http3/client.go#L36-L39
			MaxIncomingStreams: -1,
			KeepAlivePeriod:    keepAlivePeriod,
		}
		dest := dest
		dest.Network = net.Network_UDP
		return &http3.Transport{
			QUICConfig:      quicConfig,
			TLSClientConfig: h3gotlsConfig,
			Dial: func(ctx context.Context, addr string, tlsCfg *gotls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
				conn, err := internet.DialSystem(ctx, dest, streamSettings.SocketSettings)
				if err != nil {
					return nil, err
				}

				var udpConn net.PacketConn
				var udpAddr *net.UDPAddr

				switch c := conn.(type) {
				case *internet.PacketConnWrapper:
					var ok bool
					udpConn, ok = c.Conn.(*net.UDPConn)
					if !ok {
						return nil, errors.New("PacketConnWrapper does not contain a UDP connection")
					}
					udpAddr, err = net.ResolveUDPAddr("udp", c.Dest.String())
					if err != nil {
						return nil, err
					}
				case *net.UDPConn:
					udpConn = c
					udpAddr, err = net.ResolveUDPAddr("udp", c.RemoteAddr().String())
					if err != nil {
						return nil, err
					}
				default:
					udpConn = &internet.FakePacketConn{c}
					udpAddr, err = net.ResolveUDPAddr("udp", c.RemoteAddr().String())
					if err != nil {
						return nil, err
					}
				}

				return quic.DialEarly(ctx, udpConn, udpAddr, tlsCfg, cfg)
			},
		}
	}

	makeH2Transport := func() *http2.Transport {
		if keepAlivePeriod == 0 {
			keepAlivePeriod = chromeH2KeepAlivePeriod
		}
		if keepAlivePeriod < 0 {
			keepAlivePeriod = 0
		}
		return &http2.Transport{
			DialTLSContext: func(ctxInner context.Context, network string, addr string, cfg *gotls.Config) (net.Conn, error) {
				return dialContext(ctxInner)
			},
			IdleConnTimeout: connIdleTimeout,
			ReadIdleTimeout: keepAlivePeriod,
		}
	}

	makeTransport := func() *http.Transport {
		httpDialContext := func(ctxInner context.Context, network string, addr string) (net.Conn, error) {
			return dialContext(ctxInner)
		}

		return &http.Transport{
			DialTLSContext:  httpDialContext,
			DialContext:     httpDialContext,
			IdleConnTimeout: connIdleTimeout,
			// chunked transfer download with KeepAlives is buggy with
			// http.Client and our custom dial context.
			DisableKeepAlives: true,
		}
	}

	switch httpVersion {
	case "3":
		transport = makeH3Transport()
	case "2":
		transport = makeH2Transport()
	case "3+2":
		raceTransport := &raceTransport{
			h3:   makeH3Transport(),
			h2:   makeH2Transport(),
			dest: dest.NetAddr(),
		}
		transport = raceTransport.setup()
	default:
		transport = makeTransport()
	}

	client := &DefaultDialerClient{
		transportConfig: transportConfig,
		client: &http.Client{
			Transport: transport,
		},
		httpVersion:    httpVersion,
		uploadRawPool:  &sync.Pool{},
		dialUploadConn: dialContext,
	}

	return client
}

func init() {
	common.Must(internet.RegisterTransportDialer(protocolName, Dial))
}

func Dial(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) (stat.Connection, error) {
	tlsConfig := tls.ConfigFromStreamSettings(streamSettings)
	realityConfig := reality.ConfigFromStreamSettings(streamSettings)

	httpVersion := decideHTTPVersion(tlsConfig, realityConfig)
	if httpVersion == "3" {
		dest.Network = net.Network_UDP
	}

	transportConfiguration := streamSettings.ProtocolSettings.(*Config)
	var requestURL url.URL

	if tlsConfig != nil || realityConfig != nil {
		requestURL.Scheme = "https"
	} else {
		requestURL.Scheme = "http"
	}
	requestURL.Host = transportConfiguration.Host
	if requestURL.Host == "" && tlsConfig != nil {
		requestURL.Host = tlsConfig.ServerName
	}
	if requestURL.Host == "" && realityConfig != nil {
		requestURL.Host = realityConfig.ServerName
	}
	if requestURL.Host == "" {
		requestURL.Host = dest.Address.String()
	}

	sessionIdUuid := uuid.New()
	requestURL.Path = transportConfiguration.GetNormalizedPath() + sessionIdUuid.String()
	requestURL.RawQuery = transportConfiguration.GetNormalizedQuery()

	httpClient, xmuxClient := getHTTPClient(ctx, dest, streamSettings)

	mode := transportConfiguration.Mode
	if mode == "" || mode == "auto" {
		mode = "packet-up"
		if httpVersion == "2" {
			mode = "stream-up"
		}
		if realityConfig != nil && transportConfiguration.DownloadSettings == nil {
			mode = "stream-one"
		}
	}

	errors.LogInfo(ctx, fmt.Sprintf("XHTTP is dialing to %s, mode %s, HTTP version %s, host %s", dest, mode, httpVersion, requestURL.Host))

	requestURL2 := requestURL
	httpClient2 := httpClient
	xmuxClient2 := xmuxClient
	if transportConfiguration.DownloadSettings != nil {
		globalDialerAccess.Lock()
		if streamSettings.DownloadSettings == nil {
			streamSettings.DownloadSettings = common.Must2(internet.ToMemoryStreamConfig(transportConfiguration.DownloadSettings)).(*internet.MemoryStreamConfig)
			if streamSettings.SocketSettings != nil && streamSettings.SocketSettings.Penetrate {
				streamSettings.DownloadSettings.SocketSettings = streamSettings.SocketSettings
			}
		}
		globalDialerAccess.Unlock()
		memory2 := streamSettings.DownloadSettings
		dest2 := *memory2.Destination // just panic
		tlsConfig2 := tls.ConfigFromStreamSettings(memory2)
		realityConfig2 := reality.ConfigFromStreamSettings(memory2)
		httpVersion2 := decideHTTPVersion(tlsConfig2, realityConfig2)
		if httpVersion2 == "3" {
			dest2.Network = net.Network_UDP
		}
		if tlsConfig2 != nil || realityConfig2 != nil {
			requestURL2.Scheme = "https"
		} else {
			requestURL2.Scheme = "http"
		}
		config2 := memory2.ProtocolSettings.(*Config)
		requestURL2.Host = config2.Host
		if requestURL2.Host == "" && tlsConfig2 != nil {
			requestURL2.Host = tlsConfig2.ServerName
		}
		if requestURL2.Host == "" && realityConfig2 != nil {
			requestURL2.Host = realityConfig2.ServerName
		}
		if requestURL2.Host == "" {
			requestURL2.Host = dest2.Address.String()
		}
		requestURL2.Path = config2.GetNormalizedPath() + sessionIdUuid.String()
		requestURL2.RawQuery = config2.GetNormalizedQuery()
		httpClient2, xmuxClient2 = getHTTPClient(ctx, dest2, memory2)
		errors.LogInfo(ctx, fmt.Sprintf("XHTTP is downloading from %s, mode %s, HTTP version %s, host %s", dest2, "stream-down", httpVersion2, requestURL2.Host))
	}

	if xmuxClient != nil {
		xmuxClient.OpenUsage.Add(1)
	}
	if xmuxClient2 != nil && xmuxClient2 != xmuxClient {
		xmuxClient2.OpenUsage.Add(1)
	}
	var closed atomic.Int32

	reader, writer := io.Pipe()
	conn := splitConn{
		writer: writer,
		onClose: func() {
			if closed.Add(1) > 1 {
				return
			}
			if xmuxClient != nil {
				xmuxClient.OpenUsage.Add(-1)
			}
			if xmuxClient2 != nil && xmuxClient2 != xmuxClient {
				xmuxClient2.OpenUsage.Add(-1)
			}
		},
	}

	var err error
	if mode == "stream-one" {
		requestURL.Path = transportConfiguration.GetNormalizedPath()
		if xmuxClient != nil {
			xmuxClient.LeftRequests.Add(-1)
		}
		conn.reader, conn.remoteAddr, conn.localAddr, err = httpClient.OpenStream(ctx, requestURL.String(), reader, false)
		if err != nil { // browser dialer only
			return nil, err
		}
		return stat.Connection(&conn), nil
	} else { // stream-down
		if xmuxClient2 != nil {
			xmuxClient2.LeftRequests.Add(-1)
		}
		conn.reader, conn.remoteAddr, conn.localAddr, err = httpClient2.OpenStream(ctx, requestURL2.String(), nil, false)
		if err != nil { // browser dialer only
			return nil, err
		}
	}
	if mode == "stream-up" {
		if xmuxClient != nil {
			xmuxClient.LeftRequests.Add(-1)
		}
		_, _, _, err = httpClient.OpenStream(ctx, requestURL.String(), reader, true)
		if err != nil { // browser dialer only
			return nil, err
		}
		return stat.Connection(&conn), nil
	}

	scMaxEachPostBytes := transportConfiguration.GetNormalizedScMaxEachPostBytes()
	scMinPostsIntervalMs := transportConfiguration.GetNormalizedScMinPostsIntervalMs()

	if scMaxEachPostBytes.From <= buf.Size {
		panic("`scMaxEachPostBytes` should be bigger than " + strconv.Itoa(buf.Size))
	}

	maxUploadSize := scMaxEachPostBytes.rand()
	// WithSizeLimit(0) will still allow single bytes to pass, and a lot of
	// code relies on this behavior. Subtract 1 so that together with
	// uploadWriter wrapper, exact size limits can be enforced
	// uploadPipeReader, uploadPipeWriter := pipe.New(pipe.WithSizeLimit(maxUploadSize - 1))
	uploadPipeReader, uploadPipeWriter := pipe.New(pipe.WithSizeLimit(maxUploadSize - buf.Size))

	conn.writer = uploadWriter{
		uploadPipeWriter,
		maxUploadSize,
	}

	go func() {
		var seq int64
		var lastWrite time.Time

		for {
			wroteRequest := done.New()

			ctx := httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
				WroteRequest: func(httptrace.WroteRequestInfo) {
					wroteRequest.Close()
				},
			})

			// this intentionally makes a shallow-copy of the struct so we
			// can reassign Path (potentially concurrently)
			url := requestURL
			url.Path += "/" + strconv.FormatInt(seq, 10)

			seq += 1

			if scMinPostsIntervalMs.From > 0 {
				time.Sleep(time.Duration(scMinPostsIntervalMs.rand())*time.Millisecond - time.Since(lastWrite))
			}

			// by offloading the uploads into a buffered pipe, multiple conn.Write
			// calls get automatically batched together into larger POST requests.
			// without batching, bandwidth is extremely limited.
			chunk, err := uploadPipeReader.ReadMultiBuffer()
			if err != nil {
				break
			}

			lastWrite = time.Now()

			if xmuxClient != nil && (xmuxClient.LeftRequests.Add(-1) <= 0 ||
				(xmuxClient.UnreusableAt != time.Time{} && lastWrite.After(xmuxClient.UnreusableAt))) {
				httpClient, xmuxClient = getHTTPClient(ctx, dest, streamSettings)
			}

			go func() {
				err := httpClient.PostPacket(
					ctx,
					url.String(),
					&buf.MultiBufferContainer{MultiBuffer: chunk},
					int64(chunk.Len()),
				)
				wroteRequest.Close()
				if err != nil {
					errors.LogInfoInner(ctx, err, "failed to send upload")
					uploadPipeReader.Interrupt()
				}
			}()

			if _, ok := httpClient.(*DefaultDialerClient); ok {
				<-wroteRequest.Wait()
			}
		}
	}()

	return stat.Connection(&conn), nil
}

// A wrapper around pipe that ensures the size limit is exactly honored.
//
// The MultiBuffer pipe accepts any single WriteMultiBuffer call even if that
// single MultiBuffer exceeds the size limit, and then starts blocking on the
// next WriteMultiBuffer call. This means that ReadMultiBuffer can return more
// bytes than the size limit. We work around this by splitting a potentially
// too large write up into multiple.
type uploadWriter struct {
	*pipe.Writer
	maxLen int32
}

func (w uploadWriter) Write(b []byte) (int, error) {
	/*
		capacity := int(w.maxLen - w.Len())
		if capacity > 0 && capacity < len(b) {
			b = b[:capacity]
		}
	*/

	buffer := buf.New()
	n, err := buffer.Write(b)
	if err != nil {
		return 0, err
	}

	err = w.WriteMultiBuffer([]*buf.Buffer{buffer})
	if err != nil {
		return 0, err
	}
	return n, nil
}
