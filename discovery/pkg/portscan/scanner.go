// Package portscan provides TCP port scanning functionality.
package portscan

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// PortResult represents an open port on a host.
type PortResult struct {
	Host     string `json:"host"`
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Open     bool   `json:"open"`
}

// Top100Ports are the most commonly open ports.
var Top100Ports = []int{
	21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
	143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080,
	8443, 8888, 1080, 1433, 2049, 2082, 2083, 2086, 2087, 3000,
	4443, 5000, 5432, 5601, 6379, 6443, 7443, 8000, 8008, 8081,
	8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090, 8091,
	8181, 8443, 8880, 8888, 9000, 9090, 9200, 9300, 9443, 10000,
	27017, 27018,
}

// Top20Ports for quick scanning.
var Top20Ports = []int{
	21, 22, 25, 53, 80, 110, 143, 443, 993, 995,
	3306, 3389, 5432, 5900, 8080, 8443, 8888, 9090, 9200, 27017,
}

// Scan performs a TCP connect scan on the given hosts and ports.
// Uses concurrent goroutines with a configurable concurrency limit.
func Scan(hosts []string, ports []int, concurrency int, timeout time.Duration) []PortResult {
	if concurrency <= 0 {
		concurrency = 50
	}
	if timeout <= 0 {
		timeout = 3 * time.Second
	}

	var results []PortResult
	var mu sync.Mutex
	semaphore := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for _, host := range hosts {
		for _, port := range ports {
			wg.Add(1)
			semaphore <- struct{}{}

			go func(h string, p int) {
				defer wg.Done()
				defer func() { <-semaphore }()

				address := fmt.Sprintf("%s:%d", h, p)
				conn, err := net.DialTimeout("tcp", address, timeout)
				if err == nil {
					conn.Close()
					mu.Lock()
					results = append(results, PortResult{
						Host:     h,
						IP:       h,
						Port:     p,
						Protocol: "tcp",
						Open:     true,
					})
					mu.Unlock()
				}
			}(host, port)
		}
	}

	wg.Wait()
	return results
}
