package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config represents the root of the configuration file.
type Config struct {
	Server            ServerConfig            `yaml:"server" json:"server"`
	Sites             []SiteConfig            `yaml:"sites" json:"sites"`
	Rules             RulesConfig             `yaml:"rules" json:"rules"`
	Logging           LoggingConfig           `yaml:"logging" json:"logging"`
	Branding          BrandingConfig          `yaml:"branding" json:"branding"`
	RateLimit         RateLimitConfig         `yaml:"rate_limit" json:"rate_limit"`
	IPReputation      IPReputationConfig      `yaml:"ip_reputation" json:"ip_reputation"`
	BotDetection      BotDetectionConfig      `yaml:"bot_detection" json:"bot_detection"`
	RequestValidation RequestValidationConfig `yaml:"request_validation" json:"request_validation"`
	SecurityHeaders   SecurityHeadersConfig   `yaml:"security_headers" json:"security_headers"`
	ThreatLogging     ThreatLoggingConfig     `yaml:"threat_logging" json:"threat_logging"`
	Dashboard         DashboardConfig         `yaml:"dashboard" json:"dashboard"`
}

// ServerConfig configures the WAF's local listening server.
type ServerConfig struct {
	Listen string    `yaml:"listen" json:"listen"`
	TLS    TLSConfig `yaml:"tls" json:"tls"`
}

// TLSConfig configures TLS settings for the WAF server (if terminated by WAF).
type TLSConfig struct {
	Enabled bool   `yaml:"enabled" json:"enabled"`
	Cert    string `yaml:"cert" json:"cert"`
	Key     string `yaml:"key" json:"key"`
}

// SiteConfig configures a specific backend site to protect.
type SiteConfig struct {
	Domain  string    `yaml:"domain" json:"domain"`
	Backend string    `yaml:"backend" json:"backend"`
	WAF     WAFConfig `yaml:"waf" json:"waf"`
}

// WAFConfig configures Coraza for a specific site.
type WAFConfig struct {
	Enabled bool   `yaml:"enabled" json:"enabled"`
	Mode    string `yaml:"mode" json:"mode"` // on, detection_only, off
}

// RulesConfig configures where to load Coraza rules from.
type RulesConfig struct {
	CRSPath         string `yaml:"crs_path" json:"crs_path"`
	CustomRulesPath string `yaml:"custom_rules_path" json:"custom_rules_path"`
}

// LoggingConfig configures system logging and Coraza audit logging.
type LoggingConfig struct {
	Level    string `yaml:"level" json:"level"`
	File     string `yaml:"file" json:"file"`
	AuditLog string `yaml:"audit_log" json:"audit_log"`
}

// BrandingConfig configures the custom branding for block pages.
type BrandingConfig struct {
	Name string `yaml:"name" json:"name"`
	URL  string `yaml:"url" json:"url"`
}

// RateLimitPath configures path-specific rate limiting.
type RateLimitPath struct {
	Pattern           string `yaml:"pattern" json:"pattern"`
	RequestsPerMinute int    `yaml:"requests_per_minute" json:"requests_per_minute"`
}

// RateLimitConfig configures the rate limiter.
type RateLimitConfig struct {
	Enabled           bool            `yaml:"enabled" json:"enabled"`
	RequestsPerMinute int             `yaml:"requests_per_minute" json:"requests_per_minute"`
	Burst             int             `yaml:"burst" json:"burst"`
	BanThreshold      int             `yaml:"ban_threshold" json:"ban_threshold"`
	BanDuration       string          `yaml:"ban_duration" json:"ban_duration"`
	Paths             []RateLimitPath `yaml:"paths" json:"paths"`
}

// IPReputationConfig configures IP blocking and reputation.
type IPReputationConfig struct {
	Enabled   bool     `yaml:"enabled" json:"enabled"`
	Whitelist []string `yaml:"whitelist" json:"whitelist"`
	Blacklist []string `yaml:"blacklist" json:"blacklist"`
}

// BotDetectionConfig configures bot detection and search engine bot whitelisting.
type BotDetectionConfig struct {
	Enabled         bool     `yaml:"enabled" json:"enabled"`
	HoneypotPaths   []string `yaml:"honeypot_paths" json:"honeypot_paths"`
	AllowedBots     []string `yaml:"allowed_bots" json:"allowed_bots"`
	// VerifyBotsByDNS (default: true). When true, performs forward-confirmed reverse DNS (FCrDNS)
	// lookups to ensure the bot IP truly originates from the claimed search engine, preventing UA spoofing.
	// DNS lookups only happen for requests that match an AllowedBot UA pattern — never for all traffic.
	// Set to false in config to disable DNS verification if latency is a concern.
	VerifyBotsByDNS *bool    `yaml:"verify_bots_by_dns" json:"verify_bots_by_dns"`
}

// RequestValidationConfig configures payload validation.
type RequestValidationConfig struct {
	Enabled             bool     `yaml:"enabled" json:"enabled"`
	MaxBodySize         string   `yaml:"max_body_size" json:"max_body_size"`
	ResponseBodyLimit   string   `yaml:"response_body_limit" json:"response_body_limit"`
	MaxURLLength        int      `yaml:"max_url_length" json:"max_url_length"`
	MaxHeaderSize       int      `yaml:"max_header_size" json:"max_header_size"`
	MaxJSONDepth        int      `yaml:"max_json_depth" json:"max_json_depth"`
	AllowedContentTypes []string `yaml:"allowed_content_types" json:"allowed_content_types"`
	BlockedExtensions   []string `yaml:"blocked_extensions" json:"blocked_extensions"`
	ResponseBodyMimeTypes []string `yaml:"response_body_mime_types" json:"response_body_mime_types"`
}

// CORSConfig configures Cross-Origin Resource Sharing.
type CORSConfig struct {
	Enabled          bool     `yaml:"enabled" json:"enabled"`
	AllowedOrigins   []string `yaml:"allowed_origins" json:"allowed_origins"`
	AllowedMethods   []string `yaml:"allowed_methods" json:"allowed_methods"`
	AllowedHeaders   []string `yaml:"allowed_headers" json:"allowed_headers"`
	ExposedHeaders   []string `yaml:"exposed_headers" json:"exposed_headers"`
	AllowCredentials bool     `yaml:"allow_credentials" json:"allow_credentials"`
	MaxAge           int      `yaml:"max_age" json:"max_age"`
}

// SecurityHeadersConfig configures response headers.
type SecurityHeadersConfig struct {
	Enabled        bool       `yaml:"enabled" json:"enabled"`
	HSTS           bool       `yaml:"hsts" json:"hsts"`
	HSTSMaxAge     int        `yaml:"hsts_max_age" json:"hsts_max_age"`
	CSP            string     `yaml:"csp" json:"csp"`
	FrameOptions   string     `yaml:"frame_options" json:"frame_options"`
	ReferrerPolicy string     `yaml:"referrer_policy" json:"referrer_policy"`
	CORS           CORSConfig `yaml:"cors" json:"cors"`
}

// ThreatLoggingConfig configures threat intelligence logging.
type ThreatLoggingConfig struct {
	Enabled            bool   `yaml:"enabled" json:"enabled"`
	Output             string `yaml:"output" json:"output"`
	Format             string `yaml:"format" json:"format"`
	IncludeRequestBody bool   `yaml:"include_request_body" json:"include_request_body"`
}

// BasicAuthConfig configures HTTP Basic Auth.
type BasicAuthConfig struct {
	Username string `yaml:"username" json:"username"`
	Password string `yaml:"password" json:"password"`
}

// DashboardConfig configures the admin dashboard.
type DashboardConfig struct {
	Enabled   bool            `yaml:"enabled" json:"enabled"`
	Listen    string          `yaml:"listen" json:"listen"`
	BasicAuth BasicAuthConfig `yaml:"basic_auth" json:"basic_auth"`
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

	// Apply Rate Limit Defaults
	if cfg.RateLimit.RequestsPerMinute == 0 {
		cfg.RateLimit.RequestsPerMinute = 300 // default common generic rate limit
	}
	if cfg.RateLimit.Burst == 0 {
		cfg.RateLimit.Burst = 50
	}
	if cfg.RateLimit.BanThreshold == 0 {
		cfg.RateLimit.BanThreshold = 5
	}
	if cfg.RateLimit.BanDuration == "" {
		cfg.RateLimit.BanDuration = "10m"
	}

	// Apply Bot Detection Defaults
	if len(cfg.BotDetection.AllowedBots) == 0 {
		cfg.BotDetection.AllowedBots = []string{
			// Google common crawlers
			"googlebot", "google",
			// Google user-triggered fetchers (GSC URL Inspection, PageSpeed Insights, Rich Results Test, etc.)
			"google-inspectiontool", "google-site-verification", "storebot-google",
			"google-read-aloud", "google-safety", "google-extended", "lighthouse", "pagespeed",
			// Google special-case crawlers
			"adsbot-google", "apis-google", "feedfetcher-google", "mediapartners-google",
			// Other search engines
			"bingbot", "bing", "slurp", "duckduckbot", "baiduspider", "yandexbot", "yandex",
			// Social media preview fetchers
			"facebookexternalhit", "twitterbot", "whatsapp", "linkedinbot",
		}
	}
	// Default verify_bots_by_dns to true for maximum security against UA spoofing.
	// DNS lookup only occurs for requests that match an AllowedBot UA — not all traffic.
	// Operators can explicitly set verify_bots_by_dns: false in config to disable.
	if cfg.BotDetection.VerifyBotsByDNS == nil {
		v := true
		cfg.BotDetection.VerifyBotsByDNS = &v
	}

	// Apply Request Validation Defaults
	if cfg.RequestValidation.MaxBodySize == "" {
		cfg.RequestValidation.MaxBodySize = "10MB"
	}
	if cfg.RequestValidation.ResponseBodyLimit == "" {
		cfg.RequestValidation.ResponseBodyLimit = "512KB"
	}
	if len(cfg.RequestValidation.ResponseBodyMimeTypes) == 0 {
		cfg.RequestValidation.ResponseBodyMimeTypes = []string{
			"text/html", "text/plain", "application/json", "application/xml",
		}
	}
	if cfg.RequestValidation.MaxURLLength == 0 {
		cfg.RequestValidation.MaxURLLength = 8192
	}
	if cfg.RequestValidation.MaxHeaderSize == 0 {
		cfg.RequestValidation.MaxHeaderSize = 16384
	}
	if cfg.RequestValidation.MaxJSONDepth == 0 {
		cfg.RequestValidation.MaxJSONDepth = 20
	}

	// Apply Security Headers Defaults
	if cfg.SecurityHeaders.HSTSMaxAge == 0 {
		cfg.SecurityHeaders.HSTSMaxAge = 31536000
	}
	if cfg.SecurityHeaders.CSP == "" {
		cfg.SecurityHeaders.CSP = "default-src 'self'"
	}
	if cfg.SecurityHeaders.FrameOptions == "" {
		cfg.SecurityHeaders.FrameOptions = "DENY"
	}
	if cfg.SecurityHeaders.ReferrerPolicy == "" {
		cfg.SecurityHeaders.ReferrerPolicy = "strict-origin-when-cross-origin"
	}

	// Apply Threat Logging Defaults
	if cfg.ThreatLogging.Output == "" {
		cfg.ThreatLogging.Output = "threat.log"
	}
	if cfg.ThreatLogging.Format == "" {
		cfg.ThreatLogging.Format = "json"
	}

	// Apply Dashboard Defaults
	if cfg.Dashboard.Listen == "" {
		cfg.Dashboard.Listen = ":9443"
	}

	return &cfg, nil
}
