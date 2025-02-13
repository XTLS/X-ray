package quic

import (
	"context"
	"sync"
	"time"

	"github.com/xtls/quic-go"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
)

type connectionContext struct {
	rawConn *net.UDPConn
	conn    quic.Connection
}

type clientConnections struct {
	access  sync.Mutex
	conns   map[net.Destination][]*connectionContext
	// cleanup *task.Periodic
}

func isActive(s quic.Connection) bool {
	select {
	case <-s.Context().Done():
		return false
	default:
		return true
	}
}

func Dial(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) (stat.Connection, error) {
	tlsConfig := tls.ConfigFromStreamSettings(streamSettings)
	if tlsConfig == nil {
		tlsConfig = &tls.Config{
			ServerName:    internalDomain,
			AllowInsecure: true,
		}
	}

	var destAddr *net.UDPAddr
	if dest.Address.Family().IsIP() {
		destAddr = &net.UDPAddr{
			IP:   dest.Address.IP(),
			Port: int(dest.Port),
		}
	} else {
		dialerIp := internet.DestIpAddress()
		if dialerIp != nil {
			destAddr = &net.UDPAddr{
				IP:   dialerIp,
				Port: int(dest.Port),
			}
			errors.LogInfo(ctx, "quic Dial use dialer dest addr: ", destAddr)
		} else {
			addr, err := net.ResolveUDPAddr("udp", dest.NetAddr())
			if err != nil {
				return nil, err
			}
			destAddr = addr
		}
	}

	config := streamSettings.ProtocolSettings.(*Config)

	return client.openConnection(ctx, destAddr, config, tlsConfig, streamSettings.SocketSettings)
}

func (s *clientConnections) openConnection(ctx context.Context, destAddr net.Addr, config *Config, tlsConfig *tls.Config, sockopt *internet.SocketConfig) (stat.Connection, error) {
	s.access.Lock()
	defer s.access.Unlock()

	if s.conns == nil {
		s.conns = make(map[net.Destination][]*connectionContext)
	}

	dest := net.DestinationFromAddr(destAddr)

	var conns []*connectionContext
	if s, found := s.conns[dest]; found {
		conns = s
	}

	if len(conns) > 0 {
		s := conns[len(conns)-1]
		if isActive(s.conn) {
			return 	&interConn{
				ctx: ctx,
				quicConn: s.conn,
				local:  s.conn.LocalAddr(),
				remote: destAddr,
			}, nil
		} else {
			errors.LogInfo(ctx, "current quic connection is not active!")
		}
	}

	errors.LogInfo(ctx, "dialing quic to ", dest)
	rawConn, err := internet.DialSystem(ctx, dest, sockopt)
	if err != nil {
		return nil, errors.New("failed to dial to dest: ", err).AtWarning().Base(err)
	}

	quicConfig := &quic.Config{
		KeepAlivePeriod:      0,
		HandshakeIdleTimeout: time.Second * 8,
		MaxIdleTimeout:       time.Second * 300,
		EnableDatagrams:      true,
	}

	var udpConn *net.UDPConn
	switch conn := rawConn.(type) {
	case *net.UDPConn:
		udpConn = conn
	case *internet.PacketConnWrapper:
		udpConn = conn.Conn.(*net.UDPConn)
	default:
		rawConn.Close()
		return nil, errors.New("QUIC with sockopt is unsupported").AtWarning()
	}

	tr := quic.Transport{
		ConnectionIDLength: 12,
		Conn:               udpConn,
	}
	conn, err := tr.Dial(context.Background(), destAddr, tlsConfig.GetTLSConfig(tls.WithDestination(dest)), quicConfig)
	if err != nil {
		udpConn.Close()
		return nil, err
	}

	context := &connectionContext{
		conn:    conn,
		rawConn: udpConn,
	}
	s.conns[dest] = append(conns, context)
	return &interConn{
		ctx: ctx,
		quicConn: context.conn,
		local:  context.conn.LocalAddr(),
		remote: destAddr,
	}, nil
}

var client clientConnections

func init() {
	common.Must(internet.RegisterTransportDialer(protocolName, Dial))
}
