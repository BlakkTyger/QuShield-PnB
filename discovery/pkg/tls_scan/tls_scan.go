package tls_scan

import (
	"crypto/tls"
	"encoding/pem"
	"fmt"
	"net"
	"sync"
	"time"

	"qushield/discovery/pkg/dedup"
)

// TLSResult contains the dedup.TLSInfo along with its associated Host.
type TLSResult struct {
	Host string
	Info *dedup.TLSInfo
}

// versionToString maps tls constants to string representation
func versionToString(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLSv1.0"
	case tls.VersionTLS11:
		return "TLSv1.1"
	case tls.VersionTLS12:
		return "TLSv1.2"
	case tls.VersionTLS13:
		return "TLSv1.3"
	default:
		return fmt.Sprintf("UNKNOWN(%x)", v)
	}
}

// Probe concurrently dials hosts on port 443 to retrieve basic TLS Info.
func Probe(hosts []string, concurrency int, timeout time.Duration) []TLSResult {
	if concurrency <= 0 {
		concurrency = 20
	}

	var results []TLSResult
	var mu sync.Mutex
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, concurrency)

	for _, host := range hosts {
		wg.Add(1)
		semaphore <- struct{}{}

		go func(h string) {
			defer wg.Done()
			defer func() { <-semaphore }()

			info := scanHost(h, timeout)
			mu.Lock()
			results = append(results, TLSResult{
				Host: h,
				Info: info,
			})
			mu.Unlock()

		}(host)
	}

	wg.Wait()
	return results
}

func scanHost(host string, timeout time.Duration) *dedup.TLSInfo {
	dialer := &net.Dialer{
		Timeout: timeout,
	}

	config := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         host,
	}

	address := net.JoinHostPort(host, "443")
	conn, err := tls.DialWithDialer(dialer, "tcp", address, config)
	if err != nil {
		return &dedup.TLSInfo{
			Error: err.Error(),
		}
	}
	defer conn.Close()

	state := conn.ConnectionState()

	info := &dedup.TLSInfo{
		NegotiatedVersion: versionToString(state.Version),
		NegotiatedCipher:  tls.CipherSuiteName(state.CipherSuite),
		ServerName:        state.ServerName,
	}

	info.SupportedVersions = []string{info.NegotiatedVersion}
	info.CipherSuites = []dedup.CipherSuiteInfo{
		{
			Name:       info.NegotiatedCipher,
			TLSVersion: info.NegotiatedVersion,
		},
	}

	// Dump certificates to PEM
	for _, cert := range state.PeerCertificates {
		pemBlock := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}
		info.Certificates = append(info.Certificates, string(pem.EncodeToMemory(pemBlock)))
	}

	return info
}
