package localdns

import (
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/dns"
)

// Client is an implementation of dns.Client, which queries localhost for DNS.
type Client struct{}

// Type implements common.HasType.
func (*Client) Type() interface{} {
	return dns.ClientType()
}

// Start implements common.Runnable.
func (*Client) Start() error { return nil }

// Close implements common.Closable.
func (*Client) Close() error { return nil }

// LookupIP implements Client.
func (*Client) LookupIP(host string, option dns.IPOption) ([]net.IP, error) {
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, err
	}
	parsedIPs := make([]net.IP, 0, len(ips))
	ipv4 := make([]net.IP, 0, len(ips))
	ipv6 := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		parsed := net.IPAddress(ip)
		if parsed != nil {
			parsedIPs = append(parsedIPs, parsed.IP())
		}
		if len(ip) == net.IPv4len {
			ipv4 = append(ipv4, ip)
		}
		if len(ip) == net.IPv6len {
			ipv6 = append(ipv6, ip)
		}
	}
	switch {
	case option.IPv4Enable && option.IPv6Enable:
		if len(parsedIPs) > 0 {
			return parsedIPs, nil
		}
	case option.IPv4Enable:
		if len(ipv4) > 0 {
			return ipv4, nil
		}
	case option.IPv6Enable:
		if len(ipv6) > 0 {
			return ipv6, nil
		}
	}
	return nil, dns.ErrEmptyResponse
}

// New create a new dns.Client that queries localhost for DNS.
func New() *Client {
	return &Client{}
}
