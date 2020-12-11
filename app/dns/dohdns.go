package dns

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/net/cnc"
	"github.com/xtls/xray-core/common/protocol/dns"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal/pubsub"
	"github.com/xtls/xray-core/common/task"
	dns_feature "github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet"
)

// DoHNameServer implemented DNS over HTTPS (RFC8484) Wire Format,
// which is compatible with traditional dns over udp(RFC1035),
// thus most of the DOH implementation is copied from udpns.go
type DoHNameServer struct {
	dispatcher routing.Dispatcher
	sync.RWMutex
	ips        map[string]record
	pub        *pubsub.Service
	cleanup    *task.Periodic
	reqID      uint32
	clientIP   net.IP
	httpClient *http.Client
	dohURL     string
	name       string
}

// NewDoHNameServer creates DOH client object for remote resolving
func NewDoHNameServer(url *url.URL, dispatcher routing.Dispatcher, clientIP net.IP) (*DoHNameServer, error) {
	newError("DNS: created Remote DOH client for ", url.String()).AtInfo().WriteToLog()
	if clientIP != nil {
		newError("DNS: Remote DOH client ", url.String(), " uses clientip ", clientIP.String()).AtInfo().WriteToLog()
	}
	s := baseDOHNameServer(url, "DOH", clientIP)

	s.dispatcher = dispatcher
	tr := &http.Transport{
		MaxIdleConns:        30,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 30 * time.Second,
		ForceAttemptHTTP2:   true,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dispatcherCtx := context.Background()

			dest, err := net.ParseDestination(network + ":" + addr)
			if err != nil {
				return nil, err
			}

			dispatcherCtx = session.ContextWithContent(dispatcherCtx, session.ContentFromContext(ctx))
			dispatcherCtx = session.ContextWithInbound(dispatcherCtx, session.InboundFromContext(ctx))
			dispatcherCtx = log.ContextWithAccessMessage(dispatcherCtx, &log.AccessMessage{
				From:   "DoH",
				To:     s.dohURL,
				Status: log.AccessAccepted,
				Reason: "",
			})

			link, err := s.dispatcher.Dispatch(dispatcherCtx, dest)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			default:

			}
			if err != nil {
				return nil, err
			}

			cc := common.ChainedClosable{}
			if cw, ok := link.Writer.(common.Closable); ok {
				cc = append(cc, cw)
			}
			if cr, ok := link.Reader.(common.Closable); ok {
				cc = append(cc, cr)
			}
			return cnc.NewConnection(
				cnc.ConnectionInputMulti(link.Writer),
				cnc.ConnectionOutputMulti(link.Reader),
				cnc.ConnectionOnClose(cc),
			), nil
		},
	}
	s.httpClient = &http.Client{
		Timeout:   time.Second * 180,
		Transport: tr,
	}

	return s, nil
}

// NewDoHLocalNameServer creates DOH client object for local resolving
func NewDoHLocalNameServer(url *url.URL, clientIP net.IP) *DoHNameServer {
	url.Scheme = "https"
	s := baseDOHNameServer(url, "DOHL", clientIP)
	tr := &http.Transport{
		IdleConnTimeout:   90 * time.Second,
		ForceAttemptHTTP2: true,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dest, err := net.ParseDestination(network + ":" + addr)
			if err != nil {
				return nil, err
			}
			conn, err := internet.DialSystem(ctx, dest, nil)
			log.Record(&log.AccessMessage{
				From:   "DoH",
				To:     s.dohURL,
				Status: log.AccessAccepted,
				Detour: "local",
			})
			if err != nil {
				return nil, err
			}
			return conn, nil
		},
	}
	s.httpClient = &http.Client{
		Timeout:   time.Second * 180,
		Transport: tr,
	}
	newError("DNS: created Local DOH client for ", url.String()).AtInfo().WriteToLog()
	if clientIP != nil {
		newError("DNS: Local DOH client ", url.String(), " uses clientip ", clientIP.String()).AtInfo().WriteToLog()
	}
	return s
}

func baseDOHNameServer(url *url.URL, prefix string, clientIP net.IP) *DoHNameServer {
	s := &DoHNameServer{
		ips:      make(map[string]record),
		clientIP: clientIP,
		pub:      pubsub.NewService(),
		name:     prefix + "//" + url.Host,
		dohURL:   url.String(),
	}
	s.cleanup = &task.Periodic{
		Interval: time.Minute,
		Execute:  s.Cleanup,
	}

	return s
}

// Name returns client name
func (s *DoHNameServer) Name() string {
	return s.name
}

// Cleanup clears expired items from cache
func (s *DoHNameServer) Cleanup() error {
	now := time.Now()
	s.Lock()
	defer s.Unlock()

	if len(s.ips) == 0 {
		return newError("nothing to do. stopping...")
	}

	for domain, record := range s.ips {
		if record.A != nil && record.A.Expire.Before(now) {
			record.A = nil
		}
		if record.AAAA != nil && record.AAAA.Expire.Before(now) {
			record.AAAA = nil
		}

		if record.A == nil && record.AAAA == nil {
			newError(s.name, " cleanup ", domain).AtDebug().WriteToLog()
			delete(s.ips, domain)
		} else {
			s.ips[domain] = record
		}
	}

	if len(s.ips) == 0 {
		s.ips = make(map[string]record)
	}

	return nil
}

func (s *DoHNameServer) updateIP(req *dnsRequest, ipRec *IPRecord) {
	elapsed := time.Since(req.start)

	s.Lock()
	rec := s.ips[req.domain]
	updated := false

	switch req.reqType {
	case dnsmessage.TypeA:
		if isNewer(rec.A, ipRec) {
			rec.A = ipRec
			updated = true
		}
	case dnsmessage.TypeAAAA:
		addr := make([]net.Address, 0)
		for _, ip := range ipRec.IP {
			if len(ip.IP()) == net.IPv6len {
				addr = append(addr, ip)
			}
		}
		ipRec.IP = addr
		if isNewer(rec.AAAA, ipRec) {
			rec.AAAA = ipRec
			updated = true
		}
	}
	newError(s.name, " got answer: ", req.domain, " ", req.reqType, " -> ", ipRec.IP, " ", elapsed).AtInfo().WriteToLog()

	if updated {
		s.ips[req.domain] = rec
	}
	switch req.reqType {
	case dnsmessage.TypeA:
		s.pub.Publish(req.domain+"4", nil)
	case dnsmessage.TypeAAAA:
		s.pub.Publish(req.domain+"6", nil)
	}
	s.Unlock()
	common.Must(s.cleanup.Start())
}

func (s *DoHNameServer) newReqID() uint16 {
	return uint16(atomic.AddUint32(&s.reqID, 1))
}

func (s *DoHNameServer) sendQuery(ctx context.Context, domain string, option dns_feature.IPOption) {
	newError(s.name, " querying: ", domain).AtInfo().WriteToLog(session.ExportIDToError(ctx))

	if s.name+"." == "DOH//"+domain {
		newError(s.name, " tries to resolve itself! Use IP or set \"hosts\" instead.").AtError().WriteToLog(session.ExportIDToError(ctx))
		return
	}

	reqs := buildReqMsgs(domain, option, s.newReqID, genEDNS0Options(s.clientIP))

	var deadline time.Time
	if d, ok := ctx.Deadline(); ok {
		deadline = d
	} else {
		deadline = time.Now().Add(time.Second * 5)
	}

	for _, req := range reqs {
		go func(r *dnsRequest) {
			// generate new context for each req, using same context
			// may cause reqs all aborted if any one encounter an error
			dnsCtx := context.Background()

			// reserve internal dns server requested Inbound
			if inbound := session.InboundFromContext(ctx); inbound != nil {
				dnsCtx = session.ContextWithInbound(dnsCtx, inbound)
			}

			dnsCtx = session.ContextWithContent(dnsCtx, &session.Content{
				Protocol: "https",
				//SkipRoutePick: true,
			})

			// forced to use mux for DOH
			// dnsCtx = session.ContextWithMuxPrefered(dnsCtx, true)

			var cancel context.CancelFunc
			dnsCtx, cancel = context.WithDeadline(dnsCtx, deadline)
			defer cancel()

			b, err := dns.PackMessage(r.msg)
			if err != nil {
				newError("failed to pack dns query for ", domain).Base(err).AtError().WriteToLog()
				return
			}
			resp, err := s.dohHTTPSContext(dnsCtx, b.Bytes())
			if err != nil {
				newError("failed to retrieve response for ", domain).Base(err).AtError().WriteToLog()
				return
			}
			rec, err := parseResponse(resp)
			if err != nil {
				newError("failed to handle DOH response for ", domain).Base(err).AtError().WriteToLog()
				return
			}
			s.updateIP(r, rec)
		}(req)
	}
}

func (s *DoHNameServer) dohHTTPSContext(ctx context.Context, b []byte) ([]byte, error) {
	body := bytes.NewBuffer(b)
	req, err := http.NewRequest("POST", s.dohURL, body)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Accept", "application/dns-message")
	req.Header.Add("Content-Type", "application/dns-message")

	hc := s.httpClient

	resp, err := hc.Do(req.WithContext(ctx))
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(ioutil.Discard, resp.Body) // flush resp.Body so that the conn is reusable
		return nil, fmt.Errorf("DOH server returned code %d", resp.StatusCode)
	}

	return ioutil.ReadAll(resp.Body)
}

func (s *DoHNameServer) findIPsForDomain(domain string, option dns_feature.IPOption) ([]net.IP, error) {
	s.RLock()
	record, found := s.ips[domain]
	s.RUnlock()

	if !found {
		return nil, errRecordNotFound
	}

	var ips []net.Address
	var lastErr error
	if option.IPv6Enable && record.AAAA != nil && record.AAAA.RCode == dnsmessage.RCodeSuccess {
		aaaa, err := record.AAAA.getIPs()
		if err != nil {
			lastErr = err
		}
		ips = append(ips, aaaa...)
	}

	if option.IPv4Enable && record.A != nil && record.A.RCode == dnsmessage.RCodeSuccess {
		a, err := record.A.getIPs()
		if err != nil {
			lastErr = err
		}
		ips = append(ips, a...)
	}

	if len(ips) > 0 {
		return toNetIP(ips), nil
	}

	if lastErr != nil {
		return nil, lastErr
	}

	if (option.IPv4Enable && record.A != nil) || (option.IPv6Enable && record.AAAA != nil) {
		return nil, dns_feature.ErrEmptyResponse
	}

	return nil, errRecordNotFound
}

// QueryIP is called from dns.Server->queryIPTimeout
func (s *DoHNameServer) QueryIP(ctx context.Context, domain string, option dns_feature.IPOption) ([]net.IP, error) { // nolint: dupl
	fqdn := Fqdn(domain)

	ips, err := s.findIPsForDomain(fqdn, option)
	if err != errRecordNotFound {
		newError(s.name, " cache HIT ", domain, " -> ", ips).Base(err).AtDebug().WriteToLog()
		log.Record(&log.DNSLog{s.name, domain, ips, log.DNSCacheHit, 0, err})
		return ips, err
	}

	// ipv4 and ipv6 belong to different subscription groups
	var sub4, sub6 *pubsub.Subscriber
	if option.IPv4Enable {
		sub4 = s.pub.Subscribe(fqdn + "4")
		defer sub4.Close()
	}
	if option.IPv6Enable {
		sub6 = s.pub.Subscribe(fqdn + "6")
		defer sub6.Close()
	}
	done := make(chan interface{})
	go func() {
		if sub4 != nil {
			select {
			case <-sub4.Wait():
			case <-ctx.Done():
			}
		}
		if sub6 != nil {
			select {
			case <-sub6.Wait():
			case <-ctx.Done():
			}
		}
		close(done)
	}()
	s.sendQuery(ctx, fqdn, option)
	start := time.Now()

	for {
		ips, err := s.findIPsForDomain(fqdn, option)
		if err != errRecordNotFound {
			log.Record(&log.DNSLog{s.name, domain, ips, log.DNSQueried, time.Since(start), err})
			return ips, err
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-done:
		}
	}
}
