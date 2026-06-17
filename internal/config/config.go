package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config represents the root of the configuration file.
type Config struct {
	Server   ServerConfig   `yaml:"server"`
	Sites    []SiteConfig   `yaml:"sites"`
	Rules    RulesConfig    `yaml:"rules"`
	Logging  LoggingConfig  `yaml:"logging"`
	Branding BrandingConfig `yaml:"branding"`
}

// ServerConfig configures the WAF's local listening server.
type ServerConfig struct {
	Listen string    `yaml:"listen"`
	TLS    TLSConfig `yaml:"tls"`
}

// TLSConfig configures TLS settings for the WAF server (if terminated by WAF).
type TLSConfig struct {
	Enabled bool   `yaml:"enabled"`
	Cert    string `yaml:"cert"`
	Key     string `yaml:"key"`
}

// SiteConfig configures a specific backend site to protect.
type SiteConfig struct {
	Domain  string    `yaml:"domain"`
	Backend string    `yaml:"backend"`
	WAF     WAFConfig `yaml:"waf"`
}

// WAFConfig configures Coraza for a specific site.
type WAFConfig struct {
	Enabled bool   `yaml:"enabled"`
	Mode    string `yaml:"mode"` // on, detection_only, off
}

// RulesConfig configures where to load Coraza rules from.
type RulesConfig struct {
	CRSPath         string `yaml:"crs_path"`
	CustomRulesPath string `yaml:"custom_rules_path"`
}

// LoggingConfig configures system logging and Coraza audit logging.
type LoggingConfig struct {
	Level    string `yaml:"level"`
	File     string `yaml:"file"`
	AuditLog string `yaml:"audit_log"`
}

// BrandingConfig configures the custom branding for block pages.
type BrandingConfig struct {
	Name string `yaml:"name"`
	URL  string `yaml:"url"`
}

// LoadConfig reads the configuration from a file path.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Apply defaults
	if cfg.Server.Listen == "" {
		cfg.Server.Listen = ":80"
	}
	if cfg.Branding.Name == "" {
		cfg.Branding.Name = "LIM"
	}
	if cfg.Branding.URL == "" {
		cfg.Branding.URL = "https://nuralim.dev"
	}
	if cfg.Logging.Level == "" {
		cfg.Logging.Level = "info"
	}

	return &cfg, nil
}
