package engine

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nrlim/lim-waf/internal/config"
)

func TestBlockPageCSP(t *testing.T) {
	cfg := &config.Config{}
	cfg.SecurityHeaders = config.SecurityHeadersConfig{Enabled: true, CSP: "default-src 'self'"}
	handler := NewSecurityHeaders(&cfg.SecurityHeaders).Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		BlockErrorHandler(cfg)(w, r, nil)
	}))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
	csp := w.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "style-src 'unsafe-inline'") || !strings.Contains(csp, "script-src 'none'") {
		t.Errorf("block CSP does not permit inline CSS while prohibiting scripts: %q", csp)
	}
	if !strings.Contains(w.Body.String(), "<style>") || strings.Contains(w.Body.String(), "@import") || strings.Contains(w.Body.String(), "<script>") {
		t.Error("block page should contain self-contained CSS and no external fonts or scripts")
	}
}
