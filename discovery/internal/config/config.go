// Package config loads configuration from environment variables.
package config

import "os"

// Config holds the discovery engine configuration.
type Config struct {
	// API keys for enriched subdomain enumeration
	SecurityTrailsKey string
	ShodanKey         string
	VirusTotalKey     string
	CensysID          string
	CensysSecret      string

	// Scanning parameters
	LogDir string
}

// Load reads configuration from environment variables.
func Load() *Config {
	logDir := os.Getenv("LOG_DIR")
	if logDir == "" {
		logDir = "../logs"
	}

	return &Config{
		SecurityTrailsKey: os.Getenv("SECURITYTRAILS_API_KEY"),
		ShodanKey:         os.Getenv("SHODAN_API_KEY"),
		VirusTotalKey:     os.Getenv("VIRUSTOTAL_API_KEY"),
		CensysID:          os.Getenv("CENSYS_API_ID"),
		CensysSecret:      os.Getenv("CENSYS_API_SECRET"),
		LogDir:            logDir,
	}
}

// APIKeysMap returns API keys as a map for subfinder.
func (c *Config) APIKeysMap() map[string]string {
	keys := make(map[string]string)
	if c.SecurityTrailsKey != "" {
		keys["securitytrails"] = c.SecurityTrailsKey
	}
	if c.ShodanKey != "" {
		keys["shodan"] = c.ShodanKey
	}
	if c.VirusTotalKey != "" {
		keys["virustotal"] = c.VirusTotalKey
	}
	if c.CensysID != "" {
		keys["censys"] = c.CensysID + ":" + c.CensysSecret
	}
	return keys
}
