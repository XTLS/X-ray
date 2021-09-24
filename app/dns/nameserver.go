package dns

import (
	"context"
	"net/url"
	"strings"
	"time"

	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/strmatcher"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/routing"
)

// Server is the interface for Name Server.
type Server interface {
	// Name of the Client.
	Name() string
	// QueryIP sends IP queries to its configured server.
	QueryIP(ctx context.Context, domain string, clientIP net.IP, option dns.IPOption, disableCache bool) ([]net.IP, error)
}

// Client is the interface for DNS client.
type Client struct {
	server       Server
	clientIP     net.IP
	skipFallback bool
	domains      []string
	expectIPs    []*router.GeoIPMatcher
}

var errExpectedIPNonMatch = errors.New("expectIPs not match")

// NewServer creates a name server object according to the network destination url.
func NewServer(dest net.Destination, dispatcher routing.Dispatcher) (Server, error) {
	if address := dest.Address; address.Family().IsDomain() {
		u, err := url.Parse(address.Domain())
		if err != nil {
			return nil, err
		}
		switch {
		case strings.EqualFold(u.String(), "localhost"):
			return NewLocalNameServer(), nil
		case strings.EqualFold(u.Scheme, "https"): // DOH Remote mode
			return NewDoHNameServer(u, dispatcher)
		case strings.EqualFold(u.Scheme, "https+local"): // DOH Local mode
			return NewDoHLocalNameServer(u), nil
		case strings.EqualFold(u.Scheme, "quic+local"): // DNS-over-QUIC Local mode
			return NewQUICNameServer(u)
		case strings.EqualFold(u.Scheme, "tcp"): // DNS-over-TCP Remote mode
			return NewTCPNameServer(u, dispatcher)
		case strings.EqualFold(u.Scheme, "tcp+local"): // DNS-over-TCP Local mode
			return NewTCPLocalNameServer(u)
		case strings.EqualFold(u.String(), "fakedns"):
			return NewFakeDNSServer(), nil
		}
	}
	if dest.Network == net.Network_Unknown {
		dest.Network = net.Network_UDP
	}
	if dest.Network == net.Network_UDP { // UDP classic DNS mode
		return NewClassicNameServer(dest, dispatcher), nil
	}
	return nil, newError("No available name server could be created from ", dest).AtWarning()
}

// NewClient creates a DNS client managing a name server with client IP, domain rules and expected IPs.
func NewClient(ctx context.Context, ns *NameServer, clientIP net.IP, container router.GeoIPMatcherContainer, matcherInfos *[]*DomainMatcherInfo, updateDomainRule func(strmatcher.Matcher, int, []*DomainMatcherInfo) error) (*Client, error) {
	client := &Client{}

	err := core.RequireFeatures(ctx, func(dispatcher routing.Dispatcher) error {
		// Create a new server for each client for now
		server, err := NewServer(ns.Address.AsDestination(), dispatcher)
		if err != nil {
			return newError("failed to create nameserver").Base(err).AtWarning()
		}

		// Priotize local domains with specific TLDs or without any dot to local DNS
		if _, isLocalDNS := server.(*LocalNameServer); isLocalDNS {
			ns.PrioritizedDomain = append(ns.PrioritizedDomain, localTLDsAndDotlessDomains...)
			ns.OriginalRules = append(ns.OriginalRules, localTLDsAndDotlessDomainsRule)
			// The following lines is a solution to avoid core panics（rule index out of range） when setting `localhost` DNS client in config.
			// Because the `localhost` DNS client will apend len(localTLDsAndDotlessDomains) rules into matcherInfos to match `geosite:private` default rule.
			// But `matcherInfos` has no enough length to add rules, which leads to core panics (rule index out of range).
			// To avoid this, the length of `matcherInfos` must be equal to the expected, so manually append it with Golang default zero value first for later modification.
			// Related issues:
			// https://github.com/v2fly/v2ray-core/issues/529
			// https://github.com/v2fly/v2ray-core/issues/719
			for i := 0; i < len(localTLDsAndDotlessDomains); i++ {
				*matcherInfos = append(*matcherInfos, &DomainMatcherInfo{
					clientIdx:     uint16(0),
					domainRuleIdx: uint16(0),
				})
			}
		}

		// Establish domain rules
		var rules []string
		ruleCurr := 0
		ruleIter := 0
		for _, domain := range ns.PrioritizedDomain {
			domainRule, err := toStrMatcher(domain.Type, domain.Domain)
			if err != nil {
				return newError("failed to create prioritized domain").Base(err).AtWarning()
			}
			originalRuleIdx := ruleCurr
			if ruleCurr < len(ns.OriginalRules) {
				rule := ns.OriginalRules[ruleCurr]
				if ruleCurr >= len(rules) {
					rules = append(rules, rule.Rule)
				}
				ruleIter++
				if ruleIter >= int(rule.Size) {
					ruleIter = 0
					ruleCurr++
				}
			} else { // No original rule, generate one according to current domain matcher (majorly for compatibility with tests)
				rules = append(rules, domainRule.String())
				ruleCurr++
			}
			err = updateDomainRule(domainRule, originalRuleIdx, *matcherInfos)
			if err != nil {
				return newError("failed to create prioritized domain").Base(err).AtWarning()
			}
		}

		// Establish expected IPs
		var matchers []*router.GeoIPMatcher
		for _, geoip := range ns.Geoip {
			matcher, err := container.Add(geoip)
			if err != nil {
				return newError("failed to create ip matcher").Base(err).AtWarning()
			}
			matchers = append(matchers, matcher)
		}

		if len(clientIP) > 0 {
			switch ns.Address.Address.GetAddress().(type) {
			case *net.IPOrDomain_Domain:
				newError("DNS: client ", ns.Address.Address.GetDomain(), " uses clientIP ", clientIP.String()).AtInfo().WriteToLog()
			case *net.IPOrDomain_Ip:
				newError("DNS: client ", ns.Address.Address.GetIp(), " uses clientIP ", clientIP.String()).AtInfo().WriteToLog()
			}
		}

		client.server = server
		client.clientIP = clientIP
		client.skipFallback = ns.SkipFallback
		client.domains = rules
		client.expectIPs = matchers
		return nil
	})
	return client, err
}

// NewSimpleClient creates a DNS client with a simple destination.
func NewSimpleClient(ctx context.Context, endpoint *net.Endpoint, clientIP net.IP) (*Client, error) {
	client := &Client{}
	err := core.RequireFeatures(ctx, func(dispatcher routing.Dispatcher) error {
		server, err := NewServer(endpoint.AsDestination(), dispatcher)
		if err != nil {
			return newError("failed to create nameserver").Base(err).AtWarning()
		}
		client.server = server
		client.clientIP = clientIP
		return nil
	})

	if len(clientIP) > 0 {
		switch endpoint.Address.GetAddress().(type) {
		case *net.IPOrDomain_Domain:
			newError("DNS: client ", endpoint.Address.GetDomain(), " uses clientIP ", clientIP.String()).AtInfo().WriteToLog()
		case *net.IPOrDomain_Ip:
			newError("DNS: client ", endpoint.Address.GetIp(), " uses clientIP ", clientIP.String()).AtInfo().WriteToLog()
		}
	}

	return client, err
}

// Name returns the server name the client manages.
func (c *Client) Name() string {
	return c.server.Name()
}

// QueryIP send DNS query to the name server with the client's IP.
func (c *Client) QueryIP(ctx context.Context, domain string, option dns.IPOption, disableCache bool) ([]net.IP, error) {
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	ips, err := c.server.QueryIP(ctx, domain, c.clientIP, option, disableCache)
	cancel()

	if err != nil {
		return ips, err
	}
	return c.MatchExpectedIPs(domain, ips)
}

// MatchExpectedIPs matches queried domain IPs with expected IPs and returns matched ones.
func (c *Client) MatchExpectedIPs(domain string, ips []net.IP) ([]net.IP, error) {
	if len(c.expectIPs) == 0 {
		return ips, nil
	}
	newIps := []net.IP{}
	for _, ip := range ips {
		for _, matcher := range c.expectIPs {
			if matcher.Match(ip) {
				newIps = append(newIps, ip)
				break
			}
		}
	}
	if len(newIps) == 0 {
		return nil, errExpectedIPNonMatch
	}
	newError("domain ", domain, " expectIPs ", newIps, " matched at server ", c.Name()).AtDebug().WriteToLog()
	return newIps, nil
}
