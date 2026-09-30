package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nrlim/lim-waf/internal/config"
)

func TestSiteCSPOverride(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("security_headers:\n  enabled: true\n  csp: \"default-src 'none'\"\nsites:\n  - domain: wifme.id\n    backend: http://127.0.0.1:3301\n    csp: \"default-src 'self'; object-src 'none'\"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Sites[0].CSP != "default-src 'self'; object-src 'none'" || cfg.SecurityHeaders.CSP != "default-src 'none'" {
		t.Fatal("site CSP must not alter the global fallback")
	}
}

func TestLoadConfig(t *testing.T) {
	testConfigPath := filepath.Join("..", "..", "testenv", "config.yaml")
	cfg, err := config.LoadConfig(testConfigPath)
	if err != nil {
		t.Fatalf("Failed to load test config: %v", err)
	}

	if len(cfg.Sites) != 4 {
		t.Errorf("Expected 4 sites, got %d", len(cfg.Sites))
	}
	if len(cfg.BotDetection.AllowedBots) == 0 {
		t.Errorf("Expected allowed_bots to be populated")
	}
	if cfg.RequestValidation.ResponseBodyLimit != "512KB" {
		t.Errorf("Expected response_body_limit to be 512KB, got %s", cfg.RequestValidation.ResponseBodyLimit)
	}
}
