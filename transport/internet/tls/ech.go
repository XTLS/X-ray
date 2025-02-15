package tls

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
)

func ApplyECH(c *Config, config *tls.Config) error {
	var ECHConfig []byte
	var err error

	nameToQuery := c.ServerName
	var DOHServer string

	parts := strings.Split(c.Ech_DOHserver, "+")
	if len(parts) == 2 {
		// parse ECH DOH server in format of "example.com+https://1.1.1.1/dns-query"
		nameToQuery = parts[0]
		DOHServer = parts[1]
	} else if len(parts) == 1 {
		// normal format
		DOHServer = parts[0]
	} else {
		return errors.New("Invalid ECH DOH server format: ", c.Ech_DOHserver)
	}

	if len(c.EchConfig) > 0 {
		ECHConfig = c.EchConfig
	} else { // ECH config > DOH lookup
		if nameToQuery == "" {
			return errors.New("Using DOH for ECH needs serverName or use dohServer format example.com+https://1.1.1.1/dns-query")
		}
		ECHConfig, err = QueryRecord(nameToQuery, DOHServer)
		if err != nil {
			return err
		}
	}

	config.EncryptedClientHelloConfigList = ECHConfig
	return nil
}

type record struct {
	echConfig []byte
	expire    time.Time
}

var (
	dnsCache sync.Map
	// global Lock? I'm not sure if this needs finer grained locks.
	// If we do this, we will need to nest another layer of struct
	updating sync.Mutex
)

// QueryRecord returns the ECH config for given domain.
// If the record is not in cache or expired, it will query the DOH server and update the cache.
func QueryRecord(domain string, server string) ([]byte, error) {
	val, found := dnsCache.Load(domain)
	rec, _ := val.(record)
	if found && rec.expire.After(time.Now()) {
		errors.LogDebug(context.Background(), "Cache hit for domain: ", domain)
		return rec.echConfig, nil
	}

	updating.Lock()
	defer updating.Unlock()
	// Try to get cache again after lock, in case another goroutine has updated it
	// This might happen when the core tring is just stared and multiple goroutines are trying to query the same domain
	val, found = dnsCache.Load(domain)
	rec, _ = val.(record)
	if found && rec.expire.After(time.Now()) {
		errors.LogDebug(context.Background(), "ECH Config cache hit for domain: ", domain, " after trying to get update lock")
		return rec.echConfig, nil
	}

	// Query ECH config from DOH server
	errors.LogDebug(context.Background(), "Trying to query ECH config for domain: ", domain, " with ECH server: ", server)
	echConfig, ttl, err := dohQuery(server, domain)
	if err != nil {
		return []byte{}, err
	}

	// Set minimum TTL to 600 seconds
	if ttl < 600 {
		ttl = 600
	}

	// Update cache
	newRecored := record{
		echConfig: echConfig,
		expire:    time.Now().Add(time.Second * time.Duration(ttl)),
	}
	dnsCache.Store(domain, newRecored)
	return echConfig, nil
}

// dohQuery is the real func for sending type65 query for given domain to given DOH server.
// return ECH config, TTL and error
func dohQuery(server string, domain string) ([]byte, uint32, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeHTTPS)
	// always 0 in DOH
	m.Id = 0
	msg, err := m.Pack()
	if err != nil {
		return []byte{}, 0, err
	}
	// All traffic sent by core should via xray's internet.DialSystem
	// This involves the behavior of some Android VPN GUI clients
	tr := &http.Transport{
		IdleConnTimeout:   90 * time.Second,
		ForceAttemptHTTP2: true,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dest, err := net.ParseDestination(network + ":" + addr)
			if err != nil {
				return nil, err
			}
			conn, err := internet.DialSystem(ctx, dest, nil)
			if err != nil {
				return nil, err
			}
			return conn, nil
		},
	}
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: tr,
	}
	req, err := http.NewRequest("POST", server, bytes.NewReader(msg))
	if err != nil {
		return []byte{}, 0, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	resp, err := client.Do(req)
	if err != nil {
		return []byte{}, 0, err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return []byte{}, 0, err
	}
	if resp.StatusCode != http.StatusOK {
		return []byte{}, 0, errors.New("query failed with response code:", resp.StatusCode)
	}
	respMsg := new(dns.Msg)
	err = respMsg.Unpack(respBody)
	if err != nil {
		return []byte{}, 0, err
	}
	if len(respMsg.Answer) > 0 {
		for _, answer := range respMsg.Answer {
			if https, ok := answer.(*dns.HTTPS); ok && https.Hdr.Name == dns.Fqdn(domain) {
				for _, v := range https.Value {
					if echConfig, ok := v.(*dns.SVCBECHConfig); ok {
						errors.LogDebug(context.Background(), "Get ECH config:", echConfig.String(), " TTL:", respMsg.Answer[0].Header().Ttl)
						return echConfig.ECH, answer.Header().Ttl, nil
					}
				}
			}
		}
	}
	return []byte{}, 0, errors.New("no ech record found")
}
