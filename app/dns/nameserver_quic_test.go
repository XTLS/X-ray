package dns_test

import (
	"context"
	"github.com/xtls/xray-core/features/dns"
	"net/url"
	"testing"
	"time"

	. "github.com/xtls/xray-core/app/dns"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
)

func TestQUICNameServer(t *testing.T) {
	url, err := url.Parse("quic://dns.adguard.com")
	common.Must(err)
	s, err := NewQUICNameServer(url)
	common.Must(err)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
	ips, err := s.QueryIP(ctx, "google.com", net.IP(nil), dns.IPOption{
		IPv4Enable: true,
		IPv6Enable: true,
	})
	cancel()
	common.Must(err)
	if len(ips) == 0 {
		t.Error("expect some ips, but got 0")
	}
}
