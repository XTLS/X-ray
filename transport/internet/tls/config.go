package tls

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/ocsp"
	"github.com/xtls/xray-core/common/platform/filesystem"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/transport/internet"
)

var globalSessionCache = tls.NewLRUClientSessionCache(128)

// ParseCertificate converts a cert.Certificate to Certificate.
func ParseCertificate(c *cert.Certificate) *Certificate {
	if c != nil {
		certPEM, keyPEM := c.ToPEM()
		return &Certificate{
			Certificate: certPEM,
			Key:         keyPEM,
		}
	}
	return nil
}

func (c *Config) loadSelfCertPool() (*x509.CertPool, error) {
	root := x509.NewCertPool()
	for _, cert := range c.Certificate {
		if !root.AppendCertsFromPEM(cert.Certificate) {
			return nil, errors.New("failed to append cert").AtWarning()
		}
	}
	return root, nil
}

// BuildCertificates builds a list of TLS certificates from proto definition.
func (c *Config) BuildCertificates() []*tls.Certificate {
	certs := make([]*tls.Certificate, 0, len(c.Certificate))
	for _, entry := range c.Certificate {
		if entry.Usage != Certificate_ENCIPHERMENT {
			continue
		}
		getX509KeyPair := func() *tls.Certificate {
			keyPair, err := tls.X509KeyPair(entry.Certificate, entry.Key)
			if err != nil {
				errors.LogWarningInner(context.Background(), err, "ignoring invalid X509 key pair")
				return nil
			}
			keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
			if err != nil {
				errors.LogWarningInner(context.Background(), err, "ignoring invalid certificate")
				return nil
			}
			return &keyPair
		}
		if keyPair := getX509KeyPair(); keyPair != nil {
			certs = append(certs, keyPair)
		} else {
			continue
		}
		index := len(certs) - 1
		setupOcspTicker(entry, func(isReloaded, isOcspstapling bool) {
			cert := certs[index]
			if isReloaded {
				if newKeyPair := getX509KeyPair(); newKeyPair != nil {
					cert = newKeyPair
				} else {
					return
				}
			}
			if isOcspstapling {
				if newOCSPData, err := ocsp.GetOCSPForCert(cert.Certificate); err != nil {
					errors.LogWarningInner(context.Background(), err, "ignoring invalid OCSP")
				} else if string(newOCSPData) != string(cert.OCSPStaple) {
					cert.OCSPStaple = newOCSPData
				}
			}
			certs[index] = cert
		})
	}
	return certs
}

func setupOcspTicker(entry *Certificate, callback func(isReloaded, isOcspstapling bool)) {
	go func() {
		if entry.OneTimeLoading {
			return
		}
		var isOcspstapling bool
		hotReloadCertInterval := uint64(3600)
		if entry.OcspStapling != 0 {
			hotReloadCertInterval = entry.OcspStapling
			isOcspstapling = true
		}
		t := time.NewTicker(time.Duration(hotReloadCertInterval) * time.Second)
		for {
			var isReloaded bool
			if entry.CertificatePath != "" && entry.KeyPath != "" {
				newCert, err := filesystem.ReadFile(entry.CertificatePath)
				if err != nil {
					errors.LogErrorInner(context.Background(), err, "failed to parse certificate")
					return
				}
				newKey, err := filesystem.ReadFile(entry.KeyPath)
				if err != nil {
					errors.LogErrorInner(context.Background(), err, "failed to parse key")
					return
				}
				if string(newCert) != string(entry.Certificate) || string(newKey) != string(entry.Key) {
					entry.Certificate = newCert
					entry.Key = newKey
					isReloaded = true
				}
			}
			callback(isReloaded, isOcspstapling)
			<-t.C
		}
	}()
}

func isCertificateExpired(c *tls.Certificate) bool {
	if c.Leaf == nil && len(c.Certificate) > 0 {
		if pc, err := x509.ParseCertificate(c.Certificate[0]); err == nil {
			c.Leaf = pc
		}
	}

	// If leaf is not there, the certificate is probably not used yet. We trust user to provide a valid certificate.
	return c.Leaf != nil && c.Leaf.NotAfter.Before(time.Now().Add(time.Minute*2))
}

func issueCertificate(rawCA *Certificate, domain string) (*tls.Certificate, error) {
	parent, err := cert.ParseCertificate(rawCA.Certificate, rawCA.Key)
	if err != nil {
		return nil, errors.New("failed to parse raw certificate").Base(err)
	}
	newCert, err := cert.Generate(parent, cert.CommonName(domain), cert.DNSNames(domain))
	if err != nil {
		return nil, errors.New("failed to generate new certificate for ", domain).Base(err)
	}
	newCertPEM, newKeyPEM := newCert.ToPEM()
	if rawCA.BuildChain {
		newCertPEM = bytes.Join([][]byte{newCertPEM, rawCA.Certificate}, []byte("\n"))
	}
	cert, err := tls.X509KeyPair(newCertPEM, newKeyPEM)
	return &cert, err
}

func (c *Config) getCustomCA() []*Certificate {
	certs := make([]*Certificate, 0, len(c.Certificate))
	for _, certificate := range c.Certificate {
		if certificate.Usage == Certificate_AUTHORITY_ISSUE {
			certs = append(certs, certificate)
			setupOcspTicker(certificate, func(isReloaded, isOcspstapling bool) {})
		}
	}
	return certs
}

func getGetCertificateFunc(c *tls.Config, ca []*Certificate) func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	var access sync.RWMutex

	return func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		domain := hello.ServerName
		certExpired := false

		access.RLock()
		certificate, found := c.NameToCertificate[domain]
		access.RUnlock()

		if found {
			if !isCertificateExpired(certificate) {
				return certificate, nil
			}
			certExpired = true
		}

		if certExpired {
			newCerts := make([]tls.Certificate, 0, len(c.Certificates))

			access.Lock()
			for _, certificate := range c.Certificates {
				if !isCertificateExpired(&certificate) {
					newCerts = append(newCerts, certificate)
				} else if certificate.Leaf != nil {
					expTime := certificate.Leaf.NotAfter.Format(time.RFC3339)
					errors.LogInfo(context.Background(), "old certificate for ", domain, " (expire on ", expTime, ") discarded")
				}
			}

			c.Certificates = newCerts
			access.Unlock()
		}

		var issuedCertificate *tls.Certificate

		// Create a new certificate from existing CA if possible
		for _, rawCert := range ca {
			if rawCert.Usage == Certificate_AUTHORITY_ISSUE {
				newCert, err := issueCertificate(rawCert, domain)
				if err != nil {
					errors.LogInfoInner(context.Background(), err, "failed to issue new certificate for ", domain)
					continue
				}
				parsed, err := x509.ParseCertificate(newCert.Certificate[0])
				if err == nil {
					newCert.Leaf = parsed
					expTime := parsed.NotAfter.Format(time.RFC3339)
					errors.LogInfo(context.Background(), "new certificate for ", domain, " (expire on ", expTime, ") issued")
				} else {
					errors.LogInfoInner(context.Background(), err, "failed to parse new certificate for ", domain)
				}

				access.Lock()
				c.Certificates = append(c.Certificates, *newCert)
				issuedCertificate = &c.Certificates[len(c.Certificates)-1]
				access.Unlock()
				break
			}
		}

		if issuedCertificate == nil {
			return nil, errors.New("failed to create a new certificate for ", domain)
		}

		access.Lock()
		c.BuildNameToCertificate()
		access.Unlock()

		return issuedCertificate, nil
	}
}

func getNewGetCertificateFunc(certs []*tls.Certificate, rejectUnknownSNI bool) func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if len(certs) == 0 {
			return nil, errNoCertificates
		}
		sni := strings.ToLower(hello.ServerName)
		if !rejectUnknownSNI && (len(certs) == 1 || sni == "") {
			return certs[0], nil
		}
		gsni := "*"
		if index := strings.IndexByte(sni, '.'); index != -1 {
			gsni += sni[index:]
		}
		for _, keyPair := range certs {
			if keyPair.Leaf.Subject.CommonName == sni || keyPair.Leaf.Subject.CommonName == gsni {
				return keyPair, nil
			}
			for _, name := range keyPair.Leaf.DNSNames {
				if name == sni || name == gsni {
					return keyPair, nil
				}
			}
		}
		if rejectUnknownSNI {
			return nil, errNoCertificates
		}
		return certs[0], nil
	}
}

func (c *Config) parseServerName() string {
	return c.ServerName
}

func (r *RandCarrier) verifyPeerCert(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	if r.VerifyPeerCertInNames != nil {
		if len(r.VerifyPeerCertInNames) > 0 {
			certs := make([]*x509.Certificate, len(rawCerts))
			for i, asn1Data := range rawCerts {
				certs[i], _ = x509.ParseCertificate(asn1Data)
			}
			opts := x509.VerifyOptions{
				Roots:         r.RootCAs,
				CurrentTime:   time.Now(),
				Intermediates: x509.NewCertPool(),
			}
			for _, cert := range certs[1:] {
				opts.Intermediates.AddCert(cert)
			}
			for _, opts.DNSName = range r.VerifyPeerCertInNames {
				if _, err := certs[0].Verify(opts); err == nil {
					return nil
				}
			}
		}
		if r.PinnedPeerCertificateChainSha256 == nil {
			return errors.New("peer cert is invalid.")
		}
	}

	if r.PinnedPeerCertificateChainSha256 != nil {
		hashValue := GenerateCertChainHash(rawCerts)
		for _, v := range r.PinnedPeerCertificateChainSha256 {
			if hmac.Equal(hashValue, v) {
				return nil
			}
		}
		return errors.New("peer cert is unrecognized: ", base64.StdEncoding.EncodeToString(hashValue))
	}

	if r.PinnedPeerCertificatePublicKeySha256 != nil {
		for _, v := range verifiedChains {
			for _, cert := range v {
				publicHash := GenerateCertPublicKeyHash(cert)
				for _, c := range r.PinnedPeerCertificatePublicKeySha256 {
					if hmac.Equal(publicHash, c) {
						return nil
					}
				}
			}
		}
		return errors.New("peer public key is unrecognized.")
	}
	return nil
}

type RandCarrier struct {
	RootCAs                              *x509.CertPool
	VerifyPeerCertInNames                []string
	PinnedPeerCertificateChainSha256     [][]byte
	PinnedPeerCertificatePublicKeySha256 [][]byte
}

func (r *RandCarrier) Read(p []byte) (n int, err error) {
	return rand.Read(p)
}

// GetTLSConfig converts this Config into tls.Config.
func (c *Config) GetTLSConfig(opts ...Option) *tls.Config {
	root, err := c.getCertPool()
	if err != nil {
		errors.LogErrorInner(context.Background(), err, "failed to load system root certificate")
	}

	if c == nil {
		return &tls.Config{
			ClientSessionCache:     globalSessionCache,
			RootCAs:                root,
			InsecureSkipVerify:     false,
			NextProtos:             nil,
			SessionTicketsDisabled: true,
		}
	}

	randCarrier := &RandCarrier{
		RootCAs:                              root,
		VerifyPeerCertInNames:                slices.Clone(c.VerifyPeerCertInNames),
		PinnedPeerCertificateChainSha256:     c.PinnedPeerCertificateChainSha256,
		PinnedPeerCertificatePublicKeySha256: c.PinnedPeerCertificatePublicKeySha256,
	}
	config := &tls.Config{
		Rand:                   randCarrier,
		ClientSessionCache:     globalSessionCache,
		RootCAs:                root,
		InsecureSkipVerify:     c.AllowInsecure,
		NextProtos:             slices.Clone(c.NextProtocol),
		SessionTicketsDisabled: !c.EnableSessionResumption,
		VerifyPeerCertificate:  randCarrier.verifyPeerCert,
	}
	if len(c.VerifyPeerCertInNames) > 0 {
		config.InsecureSkipVerify = true
	} else {
		randCarrier.VerifyPeerCertInNames = nil
	}

	for _, opt := range opts {
		opt(config)
	}

	caCerts := c.getCustomCA()
	if len(caCerts) > 0 {
		config.GetCertificate = getGetCertificateFunc(config, caCerts)
	} else {
		config.GetCertificate = getNewGetCertificateFunc(c.BuildCertificates(), c.RejectUnknownSni)
	}

	if sn := c.parseServerName(); len(sn) > 0 {
		config.ServerName = sn
	}

	if len(c.CurvePreferences) > 0 {
		config.CurvePreferences = ParseCurveName(c.CurvePreferences)
	}

	if len(config.NextProtos) == 0 {
		config.NextProtos = []string{"h2", "http/1.1"}
	}

	switch c.MinVersion {
	case "1.0":
		config.MinVersion = tls.VersionTLS10
	case "1.1":
		config.MinVersion = tls.VersionTLS11
	case "1.2":
		config.MinVersion = tls.VersionTLS12
	case "1.3":
		config.MinVersion = tls.VersionTLS13
	}

	switch c.MaxVersion {
	case "1.0":
		config.MaxVersion = tls.VersionTLS10
	case "1.1":
		config.MaxVersion = tls.VersionTLS11
	case "1.2":
		config.MaxVersion = tls.VersionTLS12
	case "1.3":
		config.MaxVersion = tls.VersionTLS13
	}

	if len(c.CipherSuites) > 0 {
		id := make(map[string]uint16)
		for _, s := range tls.CipherSuites() {
			id[s.Name] = s.ID
		}
		for _, n := range strings.Split(c.CipherSuites, ":") {
			if id[n] != 0 {
				config.CipherSuites = append(config.CipherSuites, id[n])
			}
		}
	}

	if len(c.MasterKeyLog) > 0 && c.MasterKeyLog != "none" {
		writer, err := os.OpenFile(c.MasterKeyLog, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0644)
		if err != nil {
			errors.LogErrorInner(context.Background(), err, "failed to open ", c.MasterKeyLog, " as master key log")
		} else {
			config.KeyLogWriter = writer
		}
	}
	if len(c.EchConfig) > 0 || len(c.Ech_DOHserver) > 0 {
		err := ApplyECH(c, config)
		if err != nil {
			errors.LogError(context.Background(), err)
		}
	}

	return config
}

// Option for building TLS config.
type Option func(*tls.Config)

// WithDestination sets the server name in TLS config.
// Due to the incorrect structure of GetTLSConfig(), the config.ServerName will always be empty.
// So the real logic for SNI is:
// set it to dest -> overwrite it with servername(if it's len>0).
func WithDestination(dest net.Destination) Option {
	return func(config *tls.Config) {
		if config.ServerName == "" {
			config.ServerName = dest.Address.String()
		}
	}
}

// WithNextProto sets the ALPN values in TLS config.
func WithNextProto(protocol ...string) Option {
	return func(config *tls.Config) {
		if len(config.NextProtos) == 0 {
			config.NextProtos = protocol
		}
	}
}

// ConfigFromStreamSettings fetches Config from stream settings. Nil if not found.
func ConfigFromStreamSettings(settings *internet.MemoryStreamConfig) *Config {
	if settings == nil {
		return nil
	}
	config, ok := settings.SecuritySettings.(*Config)
	if !ok {
		return nil
	}
	return config
}

func ParseCurveName(curveNames []string) []tls.CurveID {
	curveMap := map[string]tls.CurveID{
		"curvep256":             tls.CurveP256,
		"curvep384":             tls.CurveP384,
		"curvep521":             tls.CurveP521,
		"x25519":                tls.X25519,
		"x25519kyber768draft00": 0x6399,
	}

	var curveIDs []tls.CurveID
	for _, name := range curveNames {
		if curveID, ok := curveMap[strings.ToLower(name)]; ok {
			curveIDs = append(curveIDs, curveID)
		} else {
			errors.LogWarning(context.Background(), "unsupported curve name: "+name)
		}
	}
	return curveIDs
}
