package conf

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/xtls/xray-core/app/dns"
	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common/net"
)

type NameServerConfig struct {
	Address      *Address
	ClientIP     *Address
	Port         uint16
	SkipFallback bool
	Domains      []string
	ExpectIPs    StringList
}

func (c *NameServerConfig) UnmarshalJSON(data []byte) error {
	var address Address
	if err := json.Unmarshal(data, &address); err == nil {
		c.Address = &address
		return nil
	}

	var advanced struct {
		Address      *Address   `json:"address"`
		ClientIP     *Address   `json:"clientIp"`
		Port         uint16     `json:"port"`
		SkipFallback bool       `json:"skipFallback"`
		Domains      []string   `json:"domains"`
		ExpectIPs    StringList `json:"expectIps"`
	}
	if err := json.Unmarshal(data, &advanced); err == nil {
		c.Address = advanced.Address
		c.ClientIP = advanced.ClientIP
		c.Port = advanced.Port
		c.SkipFallback = advanced.SkipFallback
		c.Domains = advanced.Domains
		c.ExpectIPs = advanced.ExpectIPs
		return nil
	}

	return newError("failed to parse name server: ", string(data))
}

func toDomainMatchingType(t router.Domain_Type) dns.DomainMatchingType {
	switch t {
	case router.Domain_Domain:
		return dns.DomainMatchingType_Subdomain
	case router.Domain_Full:
		return dns.DomainMatchingType_Full
	case router.Domain_Plain:
		return dns.DomainMatchingType_Keyword
	case router.Domain_Regex:
		return dns.DomainMatchingType_Regex
	default:
		panic("unknown domain type")
	}
}

func (c *NameServerConfig) Build() (*dns.NameServer, error) {
	if c.Address == nil {
		return nil, newError("NameServer address is not specified.")
	}

	var domains []*dns.NameServer_PriorityDomain
	var originalRules []*dns.NameServer_OriginalRule

	for _, rule := range c.Domains {
		parsedDomain, err := parseDomainRule(rule)
		if err != nil {
			return nil, newError("invalid domain rule: ", rule).Base(err)
		}

		for _, pd := range parsedDomain {
			domains = append(domains, &dns.NameServer_PriorityDomain{
				Type:   toDomainMatchingType(pd.Type),
				Domain: pd.Value,
			})
		}
		originalRules = append(originalRules, &dns.NameServer_OriginalRule{
			Rule: rule,
			Size: uint32(len(parsedDomain)),
		})
	}

	geoipList, err := toCidrList(c.ExpectIPs)
	if err != nil {
		return nil, newError("invalid IP rule: ", c.ExpectIPs).Base(err)
	}

	var myClientIP []byte
	if c.ClientIP != nil {
		if !c.ClientIP.Family().IsIP() {
			return nil, newError("not an IP address:", c.ClientIP.String())
		}
		myClientIP = []byte(c.ClientIP.IP())
	}

	return &dns.NameServer{
		Address: &net.Endpoint{
			Network: net.Network_UDP,
			Address: c.Address.Build(),
			Port:    uint32(c.Port),
		},
		ClientIp:          myClientIP,
		SkipFallback:      c.SkipFallback,
		PrioritizedDomain: domains,
		Geoip:             geoipList,
		OriginalRules:     originalRules,
	}, nil
}

var typeMap = map[router.Domain_Type]dns.DomainMatchingType{
	router.Domain_Full:   dns.DomainMatchingType_Full,
	router.Domain_Domain: dns.DomainMatchingType_Subdomain,
	router.Domain_Plain:  dns.DomainMatchingType_Keyword,
	router.Domain_Regex:  dns.DomainMatchingType_Regex,
}

// DNSConfig is a JSON serializable object for dns.Config.
type DNSConfig struct {
	Servers                []*NameServerConfig `json:"servers"`
	Hosts                  *HostsWrapper       `json:"hosts"`
	ClientIP               *Address            `json:"clientIp"`
	Tag                    string              `json:"tag"`
	QueryStrategy          string              `json:"queryStrategy"`
	DisableCache           bool                `json:"disableCache"`
	DisableFallback        bool                `json:"disableFallback"`
	DisableFallbackIfMatch bool                `json:"disableFallbackIfMatch"`
}

type HostAddress struct {
	addr  *Address
	addrs []*Address
}

// UnmarshalJSON implements encoding/json.Unmarshaler.UnmarshalJSON
func (h *HostAddress) UnmarshalJSON(data []byte) error {
	addr := new(Address)
	var addrs []*Address
	switch {
	case json.Unmarshal(data, &addr) == nil:
		h.addr = addr
	case json.Unmarshal(data, &addrs) == nil:
		h.addrs = addrs
	default:
		return newError("invalid address")
	}
	return nil
}

type HostsWrapper struct {
	Hosts map[string]*HostAddress
}

func getHostMapping(ha *HostAddress) *dns.Config_HostMapping {
	if ha.addr != nil {
		if ha.addr.Family().IsDomain() {
			return &dns.Config_HostMapping{
				ProxiedDomain: ha.addr.Domain(),
			}
		}
		return &dns.Config_HostMapping{
			Ip: [][]byte{ha.addr.IP()},
		}
	}

	ips := make([][]byte, 0, len(ha.addrs))
	for _, addr := range ha.addrs {
		if addr.Family().IsDomain() {
			return &dns.Config_HostMapping{
				ProxiedDomain: addr.Domain(),
			}
		}
		ips = append(ips, []byte(addr.IP()))
	}
	return &dns.Config_HostMapping{
		Ip: ips,
	}
}

// UnmarshalJSON implements encoding/json.Unmarshaler.UnmarshalJSON
func (m *HostsWrapper) UnmarshalJSON(data []byte) error {
	hosts := make(map[string]*HostAddress)
	err := json.Unmarshal(data, &hosts)
	if err == nil {
		m.Hosts = hosts
		return nil
	}
	return newError("invalid DNS hosts").Base(err)
}

// Build implements Buildable
func (m *HostsWrapper) Build() ([]*dns.Config_HostMapping, error) {
	mappings := make([]*dns.Config_HostMapping, 0, 20)

	domains := make([]string, 0, len(m.Hosts))
	for domain := range m.Hosts {
		domains = append(domains, domain)
	}
	sort.Strings(domains)

	for _, domain := range domains {
		switch {
		case strings.HasPrefix(domain, "domain:"):
			domainName := domain[7:]
			if len(domainName) == 0 {
				return nil, newError("empty domain type of rule: ", domain)
			}
			mapping := getHostMapping(m.Hosts[domain])
			mapping.Type = dns.DomainMatchingType_Subdomain
			mapping.Domain = domainName
			mappings = append(mappings, mapping)

		case strings.HasPrefix(domain, "geosite:"):
			listName := domain[8:]
			if len(listName) == 0 {
				return nil, newError("empty geosite rule: ", domain)
			}
			geositeList, err := loadGeositeWithAttr("geosite.dat", listName)
			if err != nil {
				return nil, newError("failed to load geosite: ", listName).Base(err)
			}
			for _, d := range geositeList {
				mapping := getHostMapping(m.Hosts[domain])
				mapping.Type = typeMap[d.Type]
				mapping.Domain = d.Value
				mappings = append(mappings, mapping)
			}

		case strings.HasPrefix(domain, "regexp:"):
			regexpVal := domain[7:]
			if len(regexpVal) == 0 {
				return nil, newError("empty regexp type of rule: ", domain)
			}
			mapping := getHostMapping(m.Hosts[domain])
			mapping.Type = dns.DomainMatchingType_Regex
			mapping.Domain = regexpVal
			mappings = append(mappings, mapping)

		case strings.HasPrefix(domain, "keyword:"):
			keywordVal := domain[8:]
			if len(keywordVal) == 0 {
				return nil, newError("empty keyword type of rule: ", domain)
			}
			mapping := getHostMapping(m.Hosts[domain])
			mapping.Type = dns.DomainMatchingType_Keyword
			mapping.Domain = keywordVal
			mappings = append(mappings, mapping)

		case strings.HasPrefix(domain, "full:"):
			fullVal := domain[5:]
			if len(fullVal) == 0 {
				return nil, newError("empty full domain type of rule: ", domain)
			}
			mapping := getHostMapping(m.Hosts[domain])
			mapping.Type = dns.DomainMatchingType_Full
			mapping.Domain = fullVal
			mappings = append(mappings, mapping)

		case strings.HasPrefix(domain, "dotless:"):
			mapping := getHostMapping(m.Hosts[domain])
			mapping.Type = dns.DomainMatchingType_Regex
			switch substr := domain[8:]; {
			case substr == "":
				mapping.Domain = "^[^.]*$"
			case !strings.Contains(substr, "."):
				mapping.Domain = "^[^.]*" + substr + "[^.]*$"
			default:
				return nil, newError("substr in dotless rule should not contain a dot: ", substr)
			}
			mappings = append(mappings, mapping)

		case strings.HasPrefix(domain, "ext:"):
			kv := strings.Split(domain[4:], ":")
			if len(kv) != 2 {
				return nil, newError("invalid external resource: ", domain)
			}
			filename := kv[0]
			list := kv[1]
			geositeList, err := loadGeositeWithAttr(filename, list)
			if err != nil {
				return nil, newError("failed to load domain list: ", list, " from ", filename).Base(err)
			}
			for _, d := range geositeList {
				mapping := getHostMapping(m.Hosts[domain])
				mapping.Type = typeMap[d.Type]
				mapping.Domain = d.Value
				mappings = append(mappings, mapping)
			}

		default:
			mapping := getHostMapping(m.Hosts[domain])
			mapping.Type = dns.DomainMatchingType_Full
			mapping.Domain = domain
			mappings = append(mappings, mapping)
		}
	}
	return mappings, nil
}

// Build implements Buildable
func (c *DNSConfig) Build() (*dns.Config, error) {
	config := &dns.Config{
		Tag:                    c.Tag,
		DisableCache:           c.DisableCache,
		DisableFallback:        c.DisableFallback,
		DisableFallbackIfMatch: c.DisableFallbackIfMatch,
	}

	if c.ClientIP != nil {
		if !c.ClientIP.Family().IsIP() {
			return nil, newError("not an IP address:", c.ClientIP.String())
		}
		config.ClientIp = []byte(c.ClientIP.IP())
	}

	config.QueryStrategy = dns.QueryStrategy_USE_IP
	switch strings.ToLower(c.QueryStrategy) {
	case "useip", "use_ip", "use-ip":
		config.QueryStrategy = dns.QueryStrategy_USE_IP
	case "useip4", "useipv4", "use_ip4", "use_ipv4", "use_ip_v4", "use-ip4", "use-ipv4", "use-ip-v4":
		config.QueryStrategy = dns.QueryStrategy_USE_IP4
	case "useip6", "useipv6", "use_ip6", "use_ipv6", "use_ip_v6", "use-ip6", "use-ipv6", "use-ip-v6":
		config.QueryStrategy = dns.QueryStrategy_USE_IP6
	}

	for _, server := range c.Servers {
		ns, err := server.Build()
		if err != nil {
			return nil, newError("failed to build nameserver").Base(err)
		}
		config.NameServer = append(config.NameServer, ns)
	}

	if c.Hosts != nil {
		staticHosts, err := c.Hosts.Build()
		if err != nil {
			return nil, newError("failed to build hosts").Base(err)
		}
		config.StaticHosts = append(config.StaticHosts, staticHosts...)
	}

	return config, nil
}
