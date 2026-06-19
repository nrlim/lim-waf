package engine

import (
	"net/http"
	"strings"
	"sync/atomic"

	"github.com/nrlim/lim-waf/internal/config"
)

// BotDetection provides heuristics-based bot blocking.
type BotDetection struct {
	config *config.BotDetectionConfig
	stats  *WAFStats
}

// NewBotDetection initializes a new BotDetection module.
func NewBotDetection(cfg *config.BotDetectionConfig, stats *WAFStats) *BotDetection {
	return &BotDetection{
		config: cfg,
		stats:  stats,
	}
}

// Middleware returns the HTTP handler that performs bot detection.
func (bd *BotDetection) Middleware(next http.Handler) http.Handler {
	if !bd.config.Enabled {
		return next
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 1. Honeypot check
		for _, hp := range bd.config.HoneypotPaths {
			if strings.HasPrefix(r.URL.Path, hp) {
				atomic.AddUint64(&bd.stats.BotDetectedReqs, 1)
				http.Error(w, "Forbidden - Malicious Bot Detected", http.StatusForbidden)
				return
			}
		}

		// 2. Missing basic headers heuristics
		// Legitimate browsers usually send 'Accept' and 'Accept-Language'
		if r.Method == http.MethodGet {
			accept := r.Header.Get("Accept")
			acceptLang := r.Header.Get("Accept-Language")
			ua := r.Header.Get("User-Agent")

			// Simple heuristic: If it has Mozilla in UA but no Accept/Accept-Language, suspicious
			if strings.Contains(strings.ToLower(ua), "mozilla") {
				if accept == "" || acceptLang == "" {
					atomic.AddUint64(&bd.stats.BotDetectedReqs, 1)
					http.Error(w, "Forbidden - Suspicious Request Headers", http.StatusForbidden)
					return
				}
			}

			// Empty UA is also suspicious unless it's an API, but for web it's bad.
			if ua == "" {
				atomic.AddUint64(&bd.stats.BotDetectedReqs, 1)
				http.Error(w, "Forbidden - Missing User-Agent", http.StatusForbidden)
				return
			}
		}

		// Proceed to next middleware
		next.ServeHTTP(w, r)
	})
}
