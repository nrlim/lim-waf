package config_test

import (
	"path/filepath"
	"testing"

	"github.com/nrlim/lim-waf/internal/config"
)

func TestLoadConfig(t *testing.T) {
	testConfigPath := filepath.Join("..", "..", "testenv", "config.yaml")
	cfg, err := config.LoadConfig(testConfigPath)
	if err != nil {
		t.Fatalf("Failed to load test config: %v", err)
	}

	if len(cfg.Sites) != 2 {
		t.Errorf("Expected 2 sites, got %d", len(cfg.Sites))
	}
	if len(cfg.BotDetection.AllowedBots) == 0 {
		t.Errorf("Expected allowed_bots to be populated")
	}
	if cfg.RequestValidation.ResponseBodyLimit != "512KB" {
		t.Errorf("Expected response_body_limit to be 512KB, got %s", cfg.RequestValidation.ResponseBodyLimit)
	}
}
