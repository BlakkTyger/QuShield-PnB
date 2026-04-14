package dedup

import (
	"testing"
)

func TestDeduplicate(t *testing.T) {
	assets := []DiscoveredAsset{
		{Hostname: "www.example.com", IPv4: "93.184.216.34", DiscoveryMethods: []string{"dns"}},
		{Hostname: "www.example.com", IPv4: "93.184.216.34", DiscoveryMethods: []string{"httpx"},
			HTTP: &HTTPInfo{StatusCode: 200, Title: "Example"}},
		{Hostname: "mail.example.com", IPv4: "93.184.216.35", DiscoveryMethods: []string{"dns"}},
	}

	result := Deduplicate(assets, 3)

	if len(result) != 2 {
		t.Fatalf("Expected 2 deduplicated assets, got %d", len(result))
	}

	// Check that www.example.com was merged
	for _, a := range result {
		if a.Hostname == "www.example.com" {
			if len(a.DiscoveryMethods) < 2 {
				t.Error("Expected merged discovery methods for www.example.com")
			}
			if a.HTTP == nil {
				t.Error("Expected HTTP info to be merged")
			}
			if a.ConfidenceScore == 0 {
				t.Error("Expected non-zero confidence score")
			}
			t.Logf("www.example.com: methods=%v, confidence=%.2f", a.DiscoveryMethods, a.ConfidenceScore)
		}
	}

	t.Logf("Dedup: %d -> %d assets", len(assets), len(result))
}

func TestKey(t *testing.T) {
	a1 := DiscoveredAsset{Hostname: "www.example.com", IPv4: "1.2.3.4"}
	a2 := DiscoveredAsset{Hostname: "WWW.EXAMPLE.COM", IPv4: "1.2.3.4"}
	a3 := DiscoveredAsset{Hostname: "other.example.com", IPv4: "1.2.3.4"}

	if a1.Key() != a2.Key() {
		t.Error("Keys should be case-insensitive")
	}
	if a1.Key() == a3.Key() {
		t.Error("Different hostnames should have different keys")
	}
}
