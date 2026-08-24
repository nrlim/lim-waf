package engine_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nrlim/lim-waf/internal/config"
	"github.com/nrlim/lim-waf/internal/engine"
)

func TestBotDetection_SmartBrowserSpoofing(t *testing.T) {
	vFalse := false
	cfg := &config.BotDetectionConfig{
		Enabled:         true,
		AllowedBots:     []string{"googlebot", "google", "google-inspectiontool", "bingbot"},
		VerifyBotsByDNS: &vFalse,
	}

	stats := &engine.WAFStats{}
	botDetect := engine.NewBotDetection(cfg, stats)

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := botDetect.Middleware(nextHandler)

	tests := []struct {
		name           string
		userAgent      string
		accept         string
		expectedStatus int
	}{
		{
			name:           "Google Inspection Tool - Should be Allowed",
			userAgent:      "Mozilla/5.0 (iPhone; CPU iPhone OS 14_7_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Mobile/15E148 Safari/604.1 (compatible; Google-InspectionTool/1.0; +https://search.google.com/search-console/inspected-url)",
			accept:         "",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Standard Chrome Browser - Should be Allowed",
			userAgent:      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			accept:         "text/html,application/xhtml+xml,application/xml;q=0.9",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Scraper Spoofing Mozilla without Accept Header - Should be Blocked 403",
			userAgent:      "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
			accept:         "",
			expectedStatus: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			if tt.userAgent != "" {
				req.Header.Set("User-Agent", tt.userAgent)
			}
			if tt.accept != "" {
				req.Header.Set("Accept", tt.accept)
			}

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("%s: expected status %d, got %d", tt.name, tt.expectedStatus, rr.Code)
			}
		})
	}
}
