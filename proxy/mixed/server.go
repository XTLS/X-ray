package mixed

import (
	"bytes"
	"context"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/routing"
	http_proxy "github.com/xtls/xray-core/proxy/http"
	socks_proxy "github.com/xtls/xray-core/proxy/socks"
	"github.com/xtls/xray-core/transport/internet"
)

const (
	socks5Version = 0x05
	socks4Version = 0x04
)

var Methods = [...][]byte{
	[]byte("GET"),
	[]byte("POST"),
	[]byte("PUT"),
	[]byte("DELETE"),
	[]byte("CONNECT"),
	[]byte("HEAD"),
	[]byte("OPTIONS"),
	[]byte("TRACE"),
	[]byte("PATCH"),
}

// Server is an HTTP proxy server.
type Server struct {
	config      *Config
	httpServer  *http_proxy.Server
	socksServer *socks_proxy.Server
}

// NewServer creates a new HTTP inbound handler.
func NewServer(ctx context.Context, config *Config) (*Server, error) {

	if config.HttpConfig == nil {
		config.HttpConfig = &http_proxy.ServerConfig{}
	}
	httpServer, err := http_proxy.NewServer(ctx, config.HttpConfig)
	if err != nil {
		return nil, err
	}

	if config.SocksConfig == nil {
		config.SocksConfig = &socks_proxy.ServerConfig{}
	}
	socksServer, err := socks_proxy.NewServer(ctx, config.SocksConfig)
	if err != nil {
		return nil, err
	}

	s := &Server{
		config:      config,
		httpServer:  httpServer,
		socksServer: socksServer,
	}

	return s, nil
}

// Network implements proxy.Inbound.
func (s *Server) Network() []net.Network {
	return append(s.httpServer.Network(), s.socksServer.Network()...)
}

func (s *Server) Process(ctx context.Context, network net.Network, conn internet.Connection, dispatcher routing.Dispatcher) error {
	switch network {
	case net.Network_UDP:
		{
			return s.socksServer.Process(ctx, network, conn, dispatcher)
		}
	}

	// copy from glider https://github.com/nadoo/glider
	cc := NewConn(conn)

	head, err := cc.Peek(1)
	if err != nil {
		return err
	}

	if head[0] == socks4Version || head[0] == socks5Version {
		return s.socksServer.Process(ctx, network, cc, dispatcher)
	}

	head, err = cc.Peek(8)
	if err != nil {
		return err
	}

	for _, method := range Methods {
		if bytes.HasPrefix(head, method) {
			return s.httpServer.Process(ctx, network, cc, dispatcher)
		}
	}

	return newError("[mixed] unknown request")
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewServer(ctx, config.(*Config))
	}))
}
