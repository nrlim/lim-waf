package engine_test

import (
	"path/filepath"
	"testing"

	"github.com/nrlim/lim-waf/internal/config"
	"github.com/nrlim/lim-waf/internal/engine"
)

func TestNewEngine(t *testing.T) {
	testConfigPath := filepath.Join("..", "..", "testenv", "config.yaml")
	cfg, err := config.LoadConfig(testConfigPath)
	if err != nil {
		t.Fatalf("Failed to load test config: %v", err)
	}

	eng, err := engine.NewEngine(cfg)
	if err != nil {
		t.Fatalf("Failed to initialize WAF Engine: %v", err)
	}

	if eng.WAF == nil {
		t.Errorf("Expected WAF engine to be non-nil")
	}
}
