package engine

import (
	"fmt"
	"log"
	"os"
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
	reqBodyLimit := int(ParseSize(cfg.RequestValidation.MaxBodySize, 10*1024*1024))
	respBodyLimit := int(ParseSize(cfg.RequestValidation.ResponseBodyLimit, 512*1024))

	// Initialize Coraza Config with Go API performance tunings
	corazaCfg := coraza.NewWAFConfig().
		WithDirectives("SecRuleEngine " + getSecRuleEngineStatus(cfg.Sites[0].WAF.Mode)).
		WithDirectives("SecRequestBodyAccess On").
		WithDirectives("SecResponseBodyAccess Off").
		WithRequestBodyLimit(reqBodyLimit).
		WithResponseBodyLimit(respBodyLimit).
		WithResponseBodyMimeTypes(cfg.RequestValidation.ResponseBodyMimeTypes).
		WithDirectives(fmt.Sprintf("SecRequestBodyLimit %d", reqBodyLimit)).
		WithDirectives(fmt.Sprintf("SecResponseBodyLimit %d", respBodyLimit)).
		WithDirectives("SecAuditEngine RelevantOnly").
		WithDirectives(`SecAuditLogRelevantStatus "^(?:5\d\d|40[0-3]|40[5-9]|4[1-9]\d)"`)

	// Load CRS rules if path is provided and setup file exists
	if cfg.Rules.CRSPath != "" {
		crsSetup := cfg.Rules.CRSPath + "/crs-setup.conf"
		if _, err := os.Stat(crsSetup); err == nil {
			corazaCfg = corazaCfg.WithDirectivesFromFile(crsSetup)

			// Scanner detection exclusion for official Google crawlers and tools.
			// Rules 913100/913110/913120 detect scanner fingerprints via User-Agent/headers,
			// which produce false positives for legitimate Google tools (Google-InspectionTool,
			// AdsBot-Google, APIs-Google, etc.) because their UA patterns overlap with scanner
			// signatures in the CRS dataset.
			//
			// Security note: Fake Google bots are blocked earlier in the middleware chain by
			// BotDetection (FCrDNS verification). By the time a request reaches Coraza with a
			// Google UA, it has already been verified as legitimate. All other CRS rules
			// (SQLi, XSS, RCE, LFI, etc.) remain fully active for all traffic.
			corazaCfg = corazaCfg.WithDirectives(`SecRule REQUEST_HEADERS:User-Agent "@rx (?i)(?:google(?:bot|-inspectiontool|-site-verification|-read-aloud|-safety|-extended)|storebot-google|adsbot-google|apis-google|feedfetcher-google|mediapartners-google)" "id:10001,phase:1,pass,nolog,ctl:ruleRemoveById=913100,ctl:ruleRemoveById=913110,ctl:ruleRemoveById=913120"`)

			corazaCfg = corazaCfg.WithDirectives("Include " + cfg.Rules.CRSPath + "/rules/*.conf")
		}
	}

	// Load Custom rules if path is provided and directory exists
	if cfg.Rules.CustomRulesPath != "" {
		if _, err := os.Stat(cfg.Rules.CustomRulesPath); err == nil {
			corazaCfg = corazaCfg.WithDirectives("Include " + cfg.Rules.CustomRulesPath + "/*.conf")
		}
	}

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
