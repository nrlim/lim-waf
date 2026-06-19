package engine

import (
	"fmt"
	"log"
	"time"

	"github.com/corazawaf/coraza/v3"
	"github.com/nrlim/lim-waf/internal/config"
)

// WAFStats holds atomic counters for the engine.
type WAFStats struct {
	TotalRequests      uint64
	BlockedRequests    uint64
	RateLimitedReqs    uint64
	BotDetectedReqs    uint64
	IPBlockedReqs      uint64
	ValidationFailReqs uint64
	StartTime          time.Time
}

// WAFEngine represents the initialized Coraza WAF engine.
type WAFEngine struct {
	WAF              coraza.WAF
	Config           *config.Config
	Stats            *WAFStats
	RateLimiter      *RateLimiter
	IPReputation     *IPReputation
	BotDetection     *BotDetection
	RequestValidator *RequestValidator
	SecurityHeaders  *SecurityHeaders
	ThreatLogger     *ThreatLogger
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

	tl, err := NewThreatLogger(&cfg.ThreatLogging)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize threat logger: %w", err)
	}

	stats := &WAFStats{
		StartTime: time.Now(),
	}

	return &WAFEngine{
		WAF:              waf,
		Config:           cfg,
		RateLimiter:      NewRateLimiter(&cfg.RateLimit, stats),
		IPReputation:     NewIPReputation(&cfg.IPReputation, stats),
		BotDetection:     NewBotDetection(&cfg.BotDetection, stats),
		RequestValidator: NewRequestValidator(&cfg.RequestValidation, stats),
		SecurityHeaders:  NewSecurityHeaders(&cfg.SecurityHeaders),
		ThreatLogger:     tl,
		Stats:            stats,
	}, nil
}

// Reload reloads the WAF engine with new configuration (hot-reload).
func (e *WAFEngine) Reload(cfg *config.Config) error {
	log.Println("Reloading WAF engine...")
	newEngine, err := NewEngine(cfg)
	if err != nil {
		return err
	}
	if e.ThreatLogger != nil {
		e.ThreatLogger.Close()
	}

	// Re-initialize middlewares with the new config but keep the old stats pointer
	newEngine.RateLimiter = NewRateLimiter(&cfg.RateLimit, e.Stats)
	newEngine.IPReputation = NewIPReputation(&cfg.IPReputation, e.Stats)
	newEngine.BotDetection = NewBotDetection(&cfg.BotDetection, e.Stats)
	newEngine.RequestValidator = NewRequestValidator(&cfg.RequestValidation, e.Stats)

	e.WAF = newEngine.WAF
	e.Config = cfg
	e.RateLimiter = newEngine.RateLimiter
	e.IPReputation = newEngine.IPReputation
	e.BotDetection = newEngine.BotDetection
	e.RequestValidator = newEngine.RequestValidator
	e.SecurityHeaders = newEngine.SecurityHeaders
	e.ThreatLogger = newEngine.ThreatLogger
	// Stats pointer remains exactly the same
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
