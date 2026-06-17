package engine

import (
	"fmt"
	"log"

	"github.com/corazawaf/coraza/v3"
	"github.com/nrlim/lim-waf/internal/config"
)

// WAFStats holds atomic counters for the engine.
type WAFStats struct {
	TotalRequests   uint64
	BlockedRequests uint64
}

// WAFEngine represents the initialized Coraza WAF engine.
type WAFEngine struct {
	WAF    coraza.WAF
	Config *config.Config
	Stats  WAFStats
}

// NewEngine initializes Coraza WAF based on the provided configuration.
func NewEngine(cfg *config.Config) (*WAFEngine, error) {
	// Initialize Coraza Config
	corazaCfg := coraza.NewWAFConfig().
		WithDirectives("SecRuleEngine " + getSecRuleEngineStatus(cfg.Sites[0].WAF.Mode)).
		WithDirectives("SecRequestBodyAccess On").
		WithDirectives("SecResponseBodyAccess On")

	// Load CRS rules if path is provided
	if cfg.Rules.CRSPath != "" {
		corazaCfg = corazaCfg.WithDirectivesFromFile(cfg.Rules.CRSPath + "/crs-setup.conf")
		corazaCfg = corazaCfg.WithDirectives("Include " + cfg.Rules.CRSPath + "/rules/*.conf")
	}

	// Load Custom rules if path is provided
	if cfg.Rules.CustomRulesPath != "" {
		corazaCfg = corazaCfg.WithDirectives("Include " + cfg.Rules.CustomRulesPath + "/*.conf")
	}

	// Disable internal error page to let proxy handle the disruption via WrapHandler
	// corazaCfg = corazaCfg.WithErrorCallback(CorazaErrorHandler(cfg))

	waf, err := coraza.NewWAF(corazaCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize WAF: %w", err)
	}

	return &WAFEngine{
		WAF:    waf,
		Config: cfg,
	}, nil
}

// Reload reloads the WAF engine with new configuration (hot-reload).
func (e *WAFEngine) Reload(cfg *config.Config) error {
	log.Println("Reloading WAF engine...")
	newEngine, err := NewEngine(cfg)
	if err != nil {
		return err
	}
	
	e.WAF = newEngine.WAF
	e.Config = cfg
	return nil
}

// getSecRuleEngineStatus converts our config mode to Coraza SecRuleEngine string.
func getSecRuleEngineStatus(mode string) string {
	switch mode {
	case "on":
		return "On"
	case "detection_only":
		return "DetectionOnly"
	case "off":
		return "Off"
	default:
		return "On" // Default to On for safety
	}
}
