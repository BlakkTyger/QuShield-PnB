// Package subdomain provides subdomain enumeration using crt.sh, CertSpotter, HackerTarget, and DNS brute-force.
package subdomain

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// crtShEntry is a JSON entry from the crt.sh API.
type crtShEntry struct {
	NameValue string `json:"name_value"`
}

// certSpotterEntry is a JSON entry from the CertSpotter API.
type certSpotterEntry struct {
	DNSNames []string `json:"dns_names"`
}

// Enumerate discovers subdomains for a domain using multiple CT logs and APIs.
// Returns a deduplicated list of explicitly resolved subdomain FQDNs.
func Enumerate(domain string) ([]string, error) {
	seen := make(map[string]bool)
	var results []string
	var mu sync.Mutex
	var wg sync.WaitGroup

	addResult := func(sub string) {
		normalized := strings.ToLower(strings.TrimSpace(sub))
		if strings.HasPrefix(normalized, "*") {
			normalized = strings.TrimPrefix(normalized, "*.")
		}
		if normalized != "" && strings.HasSuffix(normalized, domain) {
			mu.Lock()
			if !seen[normalized] {
				seen[normalized] = true
				results = append(results, normalized)
			}
			mu.Unlock()
		}
	}

	// Always include the base domain and www
	addResult(domain)
	addResult("www." + domain)

	// Fetch from crt.sh
	wg.Add(1)
	go func() {
		defer wg.Done()
		if subs, err := queryCrtSh(domain); err == nil {
			for _, s := range subs {
				addResult(s)
			}
		}
	}()

	// Fetch from CertSpotter
	wg.Add(1)
	go func() {
		defer wg.Done()
		if subs, err := queryCertSpotter(domain); err == nil {
			for _, s := range subs {
				addResult(s)
			}
		}
	}()

	// Fetch from HackerTarget
	wg.Add(1)
	go func() {
		defer wg.Done()
		if subs, err := queryHackerTarget(domain); err == nil {
			for _, s := range subs {
				addResult(s)
			}
		}
	}()

	// Common banking subdomains (financial dictionary — expanded)
	wg.Add(1)
	go func() {
		defer wg.Done()
		common := []string{
			// Infrastructure basics
			"mail", "ftp", "webmail", "smtp", "pop", "imap", "ns1", "ns2", "ns3", "ns4",
			"vpn", "vpn2", "admin", "api", "api2", "dev", "staging", "test", "uat", "cdn",
			"static", "assets", "media", "img", "images", "files", "upload",
			"mx", "mx1", "mx2", "relay", "smtp2",
			// Web & App
			"m", "mobile", "app", "app2", "portal", "secure", "login", "sso", "oauth",
			"auth", "id", "identity", "accounts", "account", "myaccount",
			"www2", "web", "web2", "beta", "demo", "sandbox",
			"dashboard", "panel", "console", "manage", "management",
			// Banking & Finance
			"netbanking", "retail", "corp", "corporate", "cbs", "upi", "swift", "payment",
			"payments", "ib", "internetbanking", "internet-banking", "onlinebanking",
			"cards", "creditcard", "debitcard", "rewards", "loyalty",
			"wholesale", "trade", "forex", "treasury", "gateway", "pg",
			"loan", "loans", "emi", "mortgage", "credit", "debit",
			"atm", "branch", "locator", "ifsc",
			"neft", "rtgs", "imps", "nach", "ecs",
			"mobilebanking", "mbk", "digitallending", "lending",
			"invest", "investment", "mf", "mutualfund", "insurance",
			"pensions", "pension", "annuity",
			"kyc", "aml", "compliance", "audit",
			// Infra & DevOps
			"monitor", "monitoring", "grafana", "kibana", "elastic", "log", "logs",
			"metrics", "prometheus", "alertmanager",
			"ci", "cd", "jenkins", "gitlab", "git",
			"registry", "docker", "k8s", "kubernetes",
			"backup", "dr", "failover", "ha",
			"ldap", "ad", "iam", "pam",
			// Subdomains common on Indian banks
			"dsj", "upi2", "bhim", "rupay", "yono", "pnbmobile",
			"retail2", "sme", "msme", "agri", "agriculture",
			"nri", "forex2", "priority",
			"helpdesk", "support", "crm", "callcenter",
			"report", "reports", "mis", "analytics",
			"waf", "fw", "firewall", "proxy", "load", "lb",
			// Common numeric/lettered variants
			"api1", "api3", "v1", "v2",
			"s1", "s2", "s3",
			"p1", "p2",
		}
		for _, prefix := range common {
			candidate := prefix + "." + domain
			addResult(candidate)
		}
	}()

	wg.Wait()

	// Verification Phase: Concurrent DNS Lookup
	return verifyDNS(results), nil
}

// verifyDNS takes a list of candidate domains and returns only those that resolve to an IP.
func verifyDNS(candidates []string) []string {
	var verified []string
	var mu sync.Mutex
	var wg sync.WaitGroup

	sema := make(chan struct{}, 100) // Max 100 concurrent lookups

	for _, host := range candidates {
		wg.Add(1)
		sema <- struct{}{}
		go func(h string) {
			defer wg.Done()
			defer func() { <-sema }()
			ips, err := net.LookupIP(h)
			if err != nil || len(ips) == 0 {
				// One retry with backoff — handles transient Docker DNS failures
				time.Sleep(500 * time.Millisecond)
				ips, err = net.LookupIP(h)
			}
			if err == nil && len(ips) > 0 {
				mu.Lock()
				verified = append(verified, h)
				mu.Unlock()
			}
		}(host)
	}

	wg.Wait()
	return verified
}

// queryCrtSh queries the crt.sh Certificate Transparency API.
func queryCrtSh(domain string) ([]string, error) {
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)
	client := &http.Client{Timeout: 25 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("bad status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var entries []crtShEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, err
	}

	var results []string
	for _, entry := range entries {
		for _, name := range strings.Split(entry.NameValue, "\n") {
			name = strings.TrimSpace(name)
			if name != "" {
				results = append(results, name)
			}
		}
	}
	return results, nil
}

// queryCertSpotter queries the CertSpotter API for subdomains.
func queryCertSpotter(domain string) ([]string, error) {
	url := fmt.Sprintf("https://api.certspotter.com/v1/issuances?domain=%s&include_subdomains=true&expand=dns_names", domain)
	client := &http.Client{Timeout: 25 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("bad status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var entries []certSpotterEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, err
	}

	var results []string
	for _, entry := range entries {
		results = append(results, entry.DNSNames...)
	}
	return results, nil
}

// queryHackerTarget queries the HackerTarget hostsearch API.
func queryHackerTarget(domain string) ([]string, error) {
	url := fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", domain)
	client := &http.Client{Timeout: 25 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("bad status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var results []string
	lines := strings.Split(string(body), "\n")
	for _, line := range lines {
		parts := strings.Split(line, ",")
		if len(parts) >= 1 && parts[0] != "" {
			results = append(results, parts[0])
		}
	}
	return results, nil
}
