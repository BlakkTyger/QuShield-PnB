// QuShield-PnB Discovery Engine
// Standalone CLI that discovers subdomains, resolves IPs, scans ports, and probes HTTP.
// Outputs a JSON file with discovered assets.
//
// Usage:
//   ./discovery-engine --domain example.com --output data/discovery/scan.json
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"qushield/discovery/internal/config"
	"qushield/discovery/internal/logger"
	"qushield/discovery/pkg/dedup"
	"qushield/discovery/pkg/httpprobe"
	"qushield/discovery/pkg/portscan"
	"qushield/discovery/pkg/subdomain"
)

func main() {
	// Parse CLI flags
	domain := flag.String("domain", "", "Target domain to scan (required)")
	output := flag.String("output", "", "Output JSON file path (required)")
	scanID := flag.String("scan-id", "standalone", "Scan ID for tracking")
	portMode := flag.String("ports", "top20", "Port scan mode: top20 or top100")
	timeout := flag.Int("timeout", 3, "Timeout per connection in seconds")
	flag.Parse()

	if *domain == "" || *output == "" {
		fmt.Fprintln(os.Stderr, "Usage: discovery-engine --domain example.com --output output.json")
		flag.PrintDefaults()
		os.Exit(1)
	}

	// Setup
	cfg := config.Load()
	log := logger.New("discovery", cfg.LogDir)
	defer log.Close()

	startTime := time.Now()
	log.Info("main", fmt.Sprintf("Starting discovery for domain: %s", *domain), map[string]interface{}{
		"scan_id": *scanID,
		"domain":  *domain,
	})

	result := dedup.DiscoveryResult{
		ScanID:    *scanID,
		Domain:    *domain,
		StartedAt: startTime.UTC().Format(time.RFC3339),
	}

	var allAssets []dedup.DiscoveredAsset

	// ─── Phase 1: Subdomain Enumeration ─────────────────────────────────
	fmt.Fprintf(os.Stderr, "[1/4] Subdomain enumeration for %s...\n", *domain)
	phaseStart := time.Now()

	subdomains, err := subdomain.Enumerate(*domain)
	if err != nil {
		log.Warn("main", fmt.Sprintf("Subdomain enumeration partial failure: %v", err))
	}

	result.Stats.SubdomainsFound = len(subdomains)
	log.Info("Enumerate", fmt.Sprintf("Found %d subdomains", len(subdomains)), map[string]interface{}{
		"domain":     *domain,
		"count":      len(subdomains),
		"duration_ms": time.Since(phaseStart).Milliseconds(),
	})
	fmt.Fprintf(os.Stderr, "    Found %d subdomains (%.1fs)\n", len(subdomains), time.Since(phaseStart).Seconds())

	// ─── Phase 2: DNS Resolution ────────────────────────────────────────
	fmt.Fprintf(os.Stderr, "[2/4] DNS resolution...\n")
	phaseStart = time.Now()

	var resolvedHosts []string
	for _, sub := range subdomains {
		ips, err := net.LookupHost(sub)
		if err == nil && len(ips) > 0 {
			resolvedHosts = append(resolvedHosts, sub)
			asset := dedup.DiscoveredAsset{
				Hostname:         sub,
				IPv4:             ips[0],
				DiscoveryMethods: []string{"dns"},
			}
			// Check for IPv6
			for _, ip := range ips {
				if net.ParseIP(ip) != nil && net.ParseIP(ip).To4() == nil {
					asset.IPv6 = ip
				}
			}
			allAssets = append(allAssets, asset)
		}
	}

	result.Stats.IPsResolved = len(resolvedHosts)
	log.Info("Resolve", fmt.Sprintf("Resolved %d/%d hostnames", len(resolvedHosts), len(subdomains)), map[string]interface{}{
		"resolved": len(resolvedHosts),
		"total":    len(subdomains),
		"duration_ms": time.Since(phaseStart).Milliseconds(),
	})
	fmt.Fprintf(os.Stderr, "    Resolved %d/%d hostnames (%.1fs)\n", len(resolvedHosts), len(subdomains), time.Since(phaseStart).Seconds())

	// ─── Phase 3: Port Scanning ─────────────────────────────────────────
	fmt.Fprintf(os.Stderr, "[3/4] Port scanning...\n")
	phaseStart = time.Now()

	ports := portscan.Top20Ports
	if *portMode == "top100" {
		ports = portscan.Top100Ports
	}

	// Collect unique IPs to scan
	ipSet := make(map[string]bool)
	for _, a := range allAssets {
		if a.IPv4 != "" {
			ipSet[a.IPv4] = true
		}
	}
	var ips []string
	for ip := range ipSet {
		ips = append(ips, ip)
	}

	portResults := portscan.Scan(ips, ports, 50, time.Duration(*timeout)*time.Second)

	// Attach ports to assets
	portsByIP := make(map[string][]dedup.PortInfo)
	for _, pr := range portResults {
		portsByIP[pr.Host] = append(portsByIP[pr.Host], dedup.PortInfo{
			Port:     pr.Port,
			Protocol: pr.Protocol,
		})
	}
	for i := range allAssets {
		if p, ok := portsByIP[allAssets[i].IPv4]; ok {
			allAssets[i].Ports = p
			allAssets[i].DiscoveryMethods = append(allAssets[i].DiscoveryMethods, "portscan")
		}
	}

	result.Stats.OpenPorts = len(portResults)
	log.Info("PortScan", fmt.Sprintf("Found %d open ports on %d IPs", len(portResults), len(ips)), map[string]interface{}{
		"open_ports": len(portResults),
		"ips_scanned": len(ips),
		"duration_ms": time.Since(phaseStart).Milliseconds(),
	})
	fmt.Fprintf(os.Stderr, "    Found %d open ports (%.1fs)\n", len(portResults), time.Since(phaseStart).Seconds())

	// ─── Phase 4: HTTP Probing ──────────────────────────────────────────
	fmt.Fprintf(os.Stderr, "[4/4] HTTP probing...\n")
	phaseStart = time.Now()

	httpResults := httpprobe.Probe(resolvedHosts, 20, 10*time.Second)

	// Attach HTTP results to assets
	httpByHost := make(map[string]*httpprobe.HTTPResult)
	for i := range httpResults {
		httpByHost[httpResults[i].Host] = &httpResults[i]
	}
	for i := range allAssets {
		if hr, ok := httpByHost[allAssets[i].Hostname]; ok {
			allAssets[i].HTTP = &dedup.HTTPInfo{
				StatusCode:  hr.StatusCode,
				Title:       hr.Title,
				WebServer:   hr.WebServer,
				TLSVersion:  hr.TLSVersion,
				ContentType: hr.ContentType,
			}
			allAssets[i].DiscoveryMethods = append(allAssets[i].DiscoveryMethods, "httpx")
		}
	}

	result.Stats.LiveHTTP = len(httpResults)
	log.Info("HTTPProbe", fmt.Sprintf("Found %d live HTTP hosts", len(httpResults)), map[string]interface{}{
		"live_http": len(httpResults),
		"duration_ms": time.Since(phaseStart).Milliseconds(),
	})
	fmt.Fprintf(os.Stderr, "    Found %d live HTTP hosts (%.1fs)\n", len(httpResults), time.Since(phaseStart).Seconds())

	// ─── Deduplication ──────────────────────────────────────────────────
	totalMethods := 3 // dns, portscan, httpx
	dedupedAssets := dedup.Deduplicate(allAssets, totalMethods)

	result.Assets = dedupedAssets
	result.CompletedAt = time.Now().UTC().Format(time.RFC3339)
	result.Stats.DurationSeconds = time.Since(startTime).Seconds()

	log.Info("main", fmt.Sprintf("Discovery complete: %d assets (%.1fs)", len(dedupedAssets), result.Stats.DurationSeconds), map[string]interface{}{
		"total_assets": len(dedupedAssets),
		"duration_seconds": result.Stats.DurationSeconds,
	})

	// ─── Write Output JSON ──────────────────────────────────────────────
	outputData, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		log.Error("main", fmt.Sprintf("Failed to marshal JSON: %v", err))
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if err := os.MkdirAll(getDir(*output), 0755); err != nil {
		log.Error("main", fmt.Sprintf("Failed to create output directory: %v", err))
	}

	if err := os.WriteFile(*output, outputData, 0644); err != nil {
		log.Error("main", fmt.Sprintf("Failed to write output: %v", err))
		fmt.Fprintf(os.Stderr, "Error writing output: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "\n✅ Discovery complete: %d assets found in %.1fs\n", len(dedupedAssets), result.Stats.DurationSeconds)
	fmt.Fprintf(os.Stderr, "   Output: %s\n", *output)
}

func getDir(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' || path[i] == '\\' {
			return path[:i]
		}
	}
	return "."
}
