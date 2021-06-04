package dns_test

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	. "github.com/xtls/xray-core/app/dns"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	dns_feature "github.com/xtls/xray-core/features/dns"
)

func TestTCPLocalNameServer(t *testing.T) {
	url, err := url.Parse("tcp+local://8.8.8.8")
	common.Must(err)
	s, err := NewTCPLocalNameServer(url)
	common.Must(err)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	ips, err := s.QueryIP(ctx, "google.com", net.IP(nil), dns_feature.IPOption{
		IPv4Enable: true,
		IPv6Enable: true,
	}, false)
	cancel()
	common.Must(err)
	if len(ips) == 0 {
		t.Error("expect some ips, but got 0")
	}
}

func TestTCPLocalNameServerWithCache(t *testing.T) {
	url, err := url.Parse("tcp+local://8.8.8.8")
	common.Must(err)
	s, err := NewTCPLocalNameServer(url)
	common.Must(err)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	ips, err := s.QueryIP(ctx, "google.com", net.IP(nil), dns_feature.IPOption{
		IPv4Enable: true,
		IPv6Enable: true,
	}, false)
	cancel()
	common.Must(err)
	if len(ips) == 0 {
		t.Error("expect some ips, but got 0")
	}

	ctx2, cancel := context.WithTimeout(context.Background(), time.Second*5)
	ips2, err := s.QueryIP(ctx2, "google.com", net.IP(nil), dns_feature.IPOption{
		IPv4Enable: true,
		IPv6Enable: true,
	}, true)
	cancel()
	common.Must(err)
	if r := cmp.Diff(ips2, ips); r != "" {
		t.Fatal(r)
	}
}
