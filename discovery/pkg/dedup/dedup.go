// Package dedup provides the shared DiscoveredAsset type and deduplication logic.
package dedup

import (
	"crypto/sha256"
	"fmt"
	"strings"
)

// PortInfo represents an open port on a host.
type PortInfo struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Service  string `json:"service,omitempty"`
}

// HTTPInfo represents HTTP probe results.
type HTTPInfo struct {
	StatusCode  int    `json:"status_code,omitempty"`
	Title       string `json:"title,omitempty"`
	WebServer   string `json:"web_server,omitempty"`
	TLSVersion  string `json:"tls_version,omitempty"`
	ContentType string `json:"content_type,omitempty"`
}

// DiscoveredAsset is the unified discovery output per asset.
type DiscoveredAsset struct {
	Hostname         string   `json:"hostname"`
	IPv4             string   `json:"ip_v4,omitempty"`
	IPv6             string   `json:"ip_v6,omitempty"`
	Ports            []PortInfo `json:"ports,omitempty"`
	HTTP             *HTTPInfo  `json:"http,omitempty"`
	DiscoveryMethods []string `json:"discovery_methods"`
	ConfidenceScore  float64  `json:"confidence_score"`
}

// Key computes a unique dedup key for this asset.
func (a *DiscoveredAsset) Key() string {
	normalized := strings.ToLower(strings.TrimSpace(a.Hostname))
	raw := fmt.Sprintf("%s|%s", normalized, a.IPv4)
	hash := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("%x", hash)
}

// DiscoveryResult is the full output of a discovery scan.
type DiscoveryResult struct {
	ScanID      string            `json:"scan_id"`
	Domain      string            `json:"domain"`
	StartedAt   string            `json:"started_at"`
	CompletedAt string            `json:"completed_at"`
	Assets      []DiscoveredAsset `json:"assets"`
	Stats       DiscoveryStats    `json:"stats"`
}

// DiscoveryStats holds summary statistics.
type DiscoveryStats struct {
	SubdomainsFound int     `json:"subdomains_found"`
	IPsResolved     int     `json:"ips_resolved"`
	OpenPorts       int     `json:"open_ports"`
	LiveHTTP        int     `json:"live_http"`
	DurationSeconds float64 `json:"duration_seconds"`
}

// Deduplicate merges duplicate assets by hostname+IP key.
// Returns deduplicated list with merged discovery methods and confidence scores.
func Deduplicate(assets []DiscoveredAsset, totalMethods int) []DiscoveredAsset {
	seen := make(map[string]*DiscoveredAsset)
	order := []string{} // preserve insertion order

	for i := range assets {
		key := assets[i].Key()
		if existing, ok := seen[key]; ok {
			// Merge: add discovery methods
			methods := make(map[string]bool)
			for _, m := range existing.DiscoveryMethods {
				methods[m] = true
			}
			for _, m := range assets[i].DiscoveryMethods {
				methods[m] = true
			}
			merged := make([]string, 0, len(methods))
			for m := range methods {
				merged = append(merged, m)
			}
			existing.DiscoveryMethods = merged

			// Merge: take richer data
			if existing.HTTP == nil && assets[i].HTTP != nil {
				existing.HTTP = assets[i].HTTP
			}
			if len(assets[i].Ports) > len(existing.Ports) {
				existing.Ports = assets[i].Ports
			}
			if assets[i].IPv4 != "" && existing.IPv4 == "" {
				existing.IPv4 = assets[i].IPv4
			}
		} else {
			copy := assets[i]
			seen[key] = &copy
			order = append(order, key)
		}
	}

	// Compute confidence scores and build result
	result := make([]DiscoveredAsset, 0, len(seen))
	for _, key := range order {
		asset := seen[key]
		if totalMethods > 0 {
			asset.ConfidenceScore = float64(len(asset.DiscoveryMethods)) / float64(totalMethods)
		}
		result = append(result, *asset)
	}

	return result
}
