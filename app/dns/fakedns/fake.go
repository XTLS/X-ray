package fakedns

import (
	"context"
	"math"
	"math/big"
	gonet "net"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/cache"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/dns"
)

type Holder struct {
	domainToIP cache.Lru
	ipRange    *gonet.IPNet

	config *FakeDnsPool
}

func (fkdns *Holder) IsIPInIPPool(ip net.Address) bool {
	return fkdns.ipRange.Contains(ip.IP())
}

func (fkdns *Holder) GetFakeIPForDomain3(domain string, IPv4, IPv6 bool) []net.Address {
	isIPv6 := fkdns.ipRange.IP.To4() == nil
	if (isIPv6 && IPv6) || (!isIPv6 && IPv4) {
		return fkdns.GetFakeIPForDomain(domain)
	}
	return []net.Address{}
}

func (*Holder) Type() interface{} {
	return (*dns.FakeDNSEngine)(nil)
}

func (fkdns *Holder) Start() error {
	return fkdns.initializeFromConfig()
}

func (fkdns *Holder) Close() error {
	fkdns.domainToIP = nil
	fkdns.ipRange = nil
	return nil
}

func NewFakeDNSHolder() (*Holder, error) {
	var fkdns *Holder
	var err error

	if fkdns, err = NewFakeDNSHolderConfigOnly(nil); err != nil {
		return nil, newError("Unable to create Fake Dns Engine").Base(err).AtError()
	}
	err = fkdns.initialize(dns.FakeIPPool, 65535)
	if err != nil {
		return nil, err
	}
	return fkdns, nil
}

func NewFakeDNSHolderConfigOnly(conf *FakeDnsPool) (*Holder, error) {
	return &Holder{nil, nil, conf}, nil
}

func (fkdns *Holder) initializeFromConfig() error {
	return fkdns.initialize(fkdns.config.IpPool, int(fkdns.config.LruSize))
}

func (fkdns *Holder) initialize(ipPoolCidr string, lruSize int) error {
	var ipRange *gonet.IPNet
	var err error

	if _, ipRange, err = gonet.ParseCIDR(ipPoolCidr); err != nil {
		return newError("Unable to parse CIDR for Fake DNS IP assignment").Base(err).AtError()
	}

	ones, bits := ipRange.Mask.Size()
	rooms := bits - ones
	if math.Log2(float64(lruSize)) >= float64(rooms) {
		return newError("LRU size is bigger than subnet size").AtError()
	}
	fkdns.domainToIP = cache.NewLru(lruSize)
	fkdns.ipRange = ipRange
	return nil
}

// GetFakeIPForDomain check and generate a fake IP for a domain name
func (fkdns *Holder) GetFakeIPForDomain(domain string) []net.Address {
	if v, ok := fkdns.domainToIP.Get(domain); ok {
		return []net.Address{v.(net.Address)}
	}
	var currentTimeMillis = uint64(time.Now().UnixNano() / 1e6)
	ones, bits := fkdns.ipRange.Mask.Size()
	rooms := bits - ones
	if rooms < 64 {
		currentTimeMillis %= (uint64(1) << rooms)
	}
	var bigIntIP = big.NewInt(0).SetBytes(fkdns.ipRange.IP)
	bigIntIP = bigIntIP.Add(bigIntIP, new(big.Int).SetUint64(currentTimeMillis))
	var ip net.Address
	for {
		ip = net.IPAddress(bigIntIP.Bytes())

		// if we run for a long time, we may go back to beginning and start seeing the IP in use
		if _, ok := fkdns.domainToIP.PeekKeyFromValue(ip); !ok {
			break
		}

		bigIntIP = bigIntIP.Add(bigIntIP, big.NewInt(1))
		if !fkdns.ipRange.Contains(bigIntIP.Bytes()) {
			bigIntIP = big.NewInt(0).SetBytes(fkdns.ipRange.IP)
		}
	}
	fkdns.domainToIP.Put(domain, ip)
	return []net.Address{ip}
}

// GetDomainFromFakeDNS check if an IP is a fake IP and have corresponding domain name
func (fkdns *Holder) GetDomainFromFakeDNS(ip net.Address) string {
	if !ip.Family().IsIP() || !fkdns.ipRange.Contains(ip.IP()) {
		return ""
	}
	if k, ok := fkdns.domainToIP.GetKeyFromValue(ip); ok {
		return k.(string)
	}
	newError("A fake ip request to ", ip, ", however there is no matching domain name in fake DNS").AtInfo().WriteToLog()
	return ""
}

// GetFakeIPRange return fake IP range from configuration
func (fkdns *Holder) GetFakeIPRange() *gonet.IPNet {
	return fkdns.ipRange
}
type HolderMulti struct {
	holders []*Holder

	config *FakeDnsPoolMulti
}

func (h *HolderMulti) IsIPInIPPool(ip net.Address) bool {
	for _, v := range h.holders {
		if v.IsIPInIPPool(ip) {
			return true
		}
	}
	return false
}

func (h *HolderMulti) GetFakeIPForDomain3(domain string, IPv4, IPv6 bool) []net.Address {
	var ret []net.Address
	for _, v := range h.holders {
		ret = append(ret, v.GetFakeIPForDomain3(domain, IPv4, IPv6)...)
	}
	return ret
}

func (h *HolderMulti) GetFakeIPForDomain(domain string) []net.Address {
	var ret []net.Address
	for _, v := range h.holders {
		ret = append(ret, v.GetFakeIPForDomain(domain)...)
	}
	return ret
}

func (h *HolderMulti) GetDomainFromFakeDNS(ip net.Address) string {
	for _, v := range h.holders {
		if domain := v.GetDomainFromFakeDNS(ip); domain != "" {
			return domain
		}
	}
	return ""
}

func (h *HolderMulti) Type() interface{} {
	return (*dns.FakeDNSEngine)(nil)
}

func (h *HolderMulti) Start() error {
	for _, v := range h.holders {
		err := v.Start()
		if err != nil {
			return newError("Cannot start all fake dns pools").Base(err)
		}
	}
	return nil
}

func (h *HolderMulti) Close() error {
	for _, v := range h.holders {
		err := v.Start()
		if err != nil {
			return newError("Cannot close all fake dns pools").Base(err)
		}
	}
	return nil
}

func (h *HolderMulti) createHolderGroups() error {
	for _, v := range h.config.Pools {
		holder, err := NewFakeDNSHolderConfigOnly(v)
		if err != nil {
			return err
		}
		h.holders = append(h.holders, holder)
	}
	return nil
}

func NewFakeDNSHolderMulti(conf *FakeDnsPoolMulti) (*HolderMulti, error) {
	holderMulti := &HolderMulti{nil, conf}
	if err := holderMulti.createHolderGroups(); err != nil {
		return nil, err
	}
	return holderMulti, nil
}

func init() {
	common.Must(common.RegisterConfig((*FakeDnsPool)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		var f *Holder
		var err error
		if f, err = NewFakeDNSHolderConfigOnly(config.(*FakeDnsPool)); err != nil {
			return nil, err
		}
		return f, nil
	}))

	common.Must(common.RegisterConfig((*FakeDnsPoolMulti)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		var f *HolderMulti
		var err error
		if f, err = NewFakeDNSHolderMulti(config.(*FakeDnsPoolMulti)); err != nil {
			return nil, err
		}
		return f, nil
	}))
}
