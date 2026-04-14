// Package httpprobe provides HTTP/HTTPS probing for live hosts.
package httpprobe

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

// HTTPResult represents the result of probing a host.
type HTTPResult struct {
	URL           string `json:"url"`
	Host          string `json:"host"`
	StatusCode    int    `json:"status_code"`
	Title         string `json:"title,omitempty"`
	WebServer     string `json:"web_server,omitempty"`
	TLSVersion    string `json:"tls_version,omitempty"`
	ContentLength int64  `json:"content_length,omitempty"`
	ContentType   string `json:"content_type,omitempty"`
}

var titleRegex = regexp.MustCompile(`(?i)<title[^>]*>([^<]+)</title>`)

// Probe checks HTTP/HTTPS connectivity on hosts.
// For each host, it tries HTTPS first, then HTTP.
func Probe(hosts []string, concurrency int, timeout time.Duration) []HTTPResult {
	if concurrency <= 0 {
		concurrency = 20
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	var results []HTTPResult
	var mu sync.Mutex
	semaphore := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	for _, host := range hosts {
		wg.Add(1)
		semaphore <- struct{}{}

		go func(h string) {
			defer wg.Done()
			defer func() { <-semaphore }()

			// Try HTTPS first, then HTTP
			for _, scheme := range []string{"https", "http"} {
				url := fmt.Sprintf("%s://%s", scheme, h)
				result := probeURL(client, url, h)
				if result != nil {
					mu.Lock()
					results = append(results, *result)
					mu.Unlock()
					return // Stop after first successful probe
				}
			}
		}(host)
	}

	wg.Wait()
	return results
}

func probeURL(client *http.Client, url, host string) *HTTPResult {
	resp, err := client.Get(url)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	result := &HTTPResult{
		URL:        url,
		Host:       host,
		StatusCode: resp.StatusCode,
		WebServer:  resp.Header.Get("Server"),
		ContentType: resp.Header.Get("Content-Type"),
		ContentLength: resp.ContentLength,
	}

	// Extract TLS version
	if resp.TLS != nil {
		switch resp.TLS.Version {
		case tls.VersionTLS10:
			result.TLSVersion = "TLSv1.0"
		case tls.VersionTLS11:
			result.TLSVersion = "TLSv1.1"
		case tls.VersionTLS12:
			result.TLSVersion = "TLSv1.2"
		case tls.VersionTLS13:
			result.TLSVersion = "TLSv1.3"
		}
	}

	// Extract page title (limited read)
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024)) // max 64KB
	if err == nil {
		matches := titleRegex.FindSubmatch(body)
		if len(matches) > 1 {
			result.Title = strings.TrimSpace(string(matches[1]))
		}
	}

	return result
}
