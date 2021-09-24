package dns

import (
	"context"
	"github.com/xtls/xray-core/features/dns"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/dns/localdns"
)

// LocalNameServer is an wrapper over local DNS feature.
type LocalNameServer struct {
	client *localdns.Client
}

// QueryIP implements Server.
func (s *LocalNameServer) QueryIP(_ context.Context, domain string, _ net.IP, option dns.IPOption, _ bool) ([]net.IP, error) {
	return s.client.LookupIP(domain, option)
}

// Name implements Server.
func (s *LocalNameServer) Name() string {
	return "localhost"
}

// NewLocalNameServer creates localdns server object for directly lookup in system DNS.
func NewLocalNameServer() *LocalNameServer {
	newError("DNS: created localhost client").AtInfo().WriteToLog()
	return &LocalNameServer{
		client: localdns.New(),
	}
}

// NewLocalDNSClient creates localdns client object for directly lookup in system DNS.
func NewLocalDNSClient() *Client {
	return &Client{server: NewLocalNameServer()}
}
