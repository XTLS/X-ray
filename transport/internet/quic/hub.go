package quic

import (
	"context"
	"time"

	"github.com/xtls/quic-go"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/common/signal/done"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/tls"
)

// Listener is an internet.Listener that listens for TCP connections.
type Listener struct {
	rawConn  *net.UDPConn
	listener *quic.Listener
	done     *done.Instance
	addConn  internet.ConnHandler
}

func (l *Listener) keepAccepting(ctx context.Context) {
	for {
		conn, err := l.listener.Accept(context.Background())
		if err != nil {
			errors.LogInfoInner(context.Background(), err, "failed to accept QUIC connection")
			if l.done.Done() {
				break
			}
			time.Sleep(time.Second)
			continue
		}
		l.addConn(&interConn{
			ctx: ctx,
			quicConn: conn,
			local:  conn.LocalAddr(),
			remote: conn.RemoteAddr(),
		})
	}
}

// Addr implements internet.Listener.Addr.
func (l *Listener) Addr() net.Addr {
	return l.listener.Addr()
}

// Close implements internet.Listener.Close.
func (l *Listener) Close() error {
	l.done.Close()
	l.listener.Close()
	l.rawConn.Close()
	return nil
}

// Listen creates a new Listener based on configurations.
func Listen(ctx context.Context, address net.Address, port net.Port, streamSettings *internet.MemoryStreamConfig, handler internet.ConnHandler) (internet.Listener, error) {
	if address.Family().IsDomain() {
		return nil, errors.New("domain address is not allows for listening quic")
	}

	tlsConfig := tls.ConfigFromStreamSettings(streamSettings)
	if tlsConfig == nil {
		tlsConfig = &tls.Config{
			Certificate: []*tls.Certificate{tls.ParseCertificate(cert.MustGenerate(nil, cert.DNSNames(internalDomain), cert.CommonName(internalDomain)))},
		}
	}

	//config := streamSettings.ProtocolSettings.(*Config)
	rawConn, err := internet.ListenSystemPacket(context.Background(), &net.UDPAddr{
		IP:   address.IP(),
		Port: int(port),
	}, streamSettings.SocketSettings)
	if err != nil {
		return nil, err
	}

	quicConfig := &quic.Config{
		KeepAlivePeriod:       0,
		HandshakeIdleTimeout:  time.Second * 8,
		MaxIdleTimeout:        time.Second * 300,
		MaxIncomingStreams:    32,
		MaxIncomingUniStreams: -1,
		EnableDatagrams:       true,
	}

	tr := quic.Transport{
		ConnectionIDLength: 12,
		Conn:               rawConn.(*net.UDPConn),
	}
	qListener, err := tr.Listen(tlsConfig.GetTLSConfig(), quicConfig)
	if err != nil {
		rawConn.Close()
		return nil, err
	}

	listener := &Listener{
		done:     done.New(),
		rawConn:  rawConn.(*net.UDPConn),
		listener: qListener,
		addConn:  handler,
	}

	go listener.keepAccepting(ctx)

	return listener, nil
}

func init() {
	common.Must(internet.RegisterTransportListener(protocolName, Listen))
}
