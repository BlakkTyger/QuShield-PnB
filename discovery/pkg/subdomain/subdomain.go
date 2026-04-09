// Package subdomain provides subdomain enumeration using crt.sh and DNS brute-force.
// For POC simplicity, we use the crt.sh JSON API (Certificate Transparency) and
// basic DNS resolution instead of importing the full subfinder library.
package subdomain

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// crtShEntry is a JSON entry from the crt.sh API.
type crtShEntry struct {
	NameValue string `json:"name_value"`
}

// Enumerate discovers subdomains for a domain using Certificate Transparency logs.
// Returns a deduplicated list of subdomain FQDNs.
func Enumerate(domain string) ([]string, error) {
	seen := make(map[string]bool)
	var results []string

	// Method 1: crt.sh CT log query
	ctSubs, err := queryCrtSh(domain)
	if err == nil {
		for _, sub := range ctSubs {
			normalized := strings.ToLower(strings.TrimSpace(sub))
			if normalized != "" && !seen[normalized] && strings.HasSuffix(normalized, domain) {
				seen[normalized] = true
				results = append(results, normalized)
			}
		}
	}

	// Always include the base domain and www
	for _, base := range []string{domain, "www." + domain} {
		if !seen[base] {
			seen[base] = true
			results = append(results, base)
		}
	}

	// Method 2: Common subdomain brute-force (quick check)
	common := []string{
		"mail", "ftp", "webmail", "smtp", "pop", "ns1", "ns2",
		"vpn", "admin", "api", "dev", "staging", "test", "cdn",
		"m", "mobile", "app", "portal", "secure", "login",
	}
	for _, prefix := range common {
		candidate := prefix + "." + domain
		if !seen[candidate] {
			// Quick DNS check
			_, err := net.LookupHost(candidate)
			if err == nil {
				seen[candidate] = true
				results = append(results, candidate)
			}
		}
	}

	return results, nil
}

// queryCrtSh queries the crt.sh Certificate Transparency API.
func queryCrtSh(domain string) ([]string, error) {
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("crt.sh request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("crt.sh returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading crt.sh response: %w", err)
	}

	var entries []crtShEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("parsing crt.sh JSON: %w", err)
	}

	var results []string
	for _, entry := range entries {
		// name_value can contain multiple names separated by newlines
		for _, name := range strings.Split(entry.NameValue, "\n") {
			name = strings.TrimSpace(name)
			// Skip wildcards
			if strings.HasPrefix(name, "*") {
				name = strings.TrimPrefix(name, "*.")
			}
			if name != "" {
				results = append(results, name)
			}
		}
	}

	return results, nil
}
