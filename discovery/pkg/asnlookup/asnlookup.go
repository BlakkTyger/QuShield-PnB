package asnlookup

import (
	"fmt"
	"net"
	"strings"
	"sync"

	"qushield/discovery/pkg/dedup"
)

// ASNResult holds the query result for an IP.
type ASNResult struct {
	IP   string
	Info *dedup.ASNInfo
}

// Lookup concurrently resolves ASN info for a list of IPv4 addresses using Team Cymru DNS.
func Lookup(ips []string, concurrency int) []ASNResult {
	if concurrency <= 0 {
		concurrency = 20
	}

	var results []ASNResult
	var mu sync.Mutex
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, concurrency)

	for _, ip := range ips {
		wg.Add(1)
		semaphore <- struct{}{}

		go func(address string) {
			defer wg.Done()
			defer func() { <-semaphore }()

			info := queryASN(address)
			if info != nil {
				mu.Lock()
				results = append(results, ASNResult{
					IP:   address,
					Info: info,
				})
				mu.Unlock()
			}
		}(ip)
	}

	wg.Wait()
	return results
}

func queryASN(ip string) *dedup.ASNInfo {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return nil
	}
	parsed = parsed.To4()
	if parsed == nil {
		return nil // Only IPv4 for Cymru right now
	}

	// Reverse IP
	reversed := fmt.Sprintf("%d.%d.%d.%d", parsed[3], parsed[2], parsed[1], parsed[0])
	query := fmt.Sprintf("%s.origin.asn.cymru.com", reversed)

	txts, err := net.LookupTXT(query)
	if err != nil || len(txts) == 0 {
		return nil
	}

	// "15169 | 8.8.8.0/24 | US | arin | 1992-12-01"
	parts := strings.Split(txts[0], "|")
	if len(parts) > 0 {
		number := strings.TrimSpace(parts[0])
		return &dedup.ASNInfo{
			Number: fmt.Sprintf("AS%s", number),
			Org:    "ASN-" + number,
		}
	}

	return nil
}
