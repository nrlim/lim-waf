package engine

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nrlim/lim-waf/internal/config"
)

func TestProxySiteCSP(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Content-Security-Policy", "default-src https:")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()
	cfg := &config.Config{
		Sites: []config.SiteConfig{
			{Domain: "wifme.id", Backend: backend.URL, CSP: "default-src 'self'"},
			{Domain: "other.example", Backend: backend.URL},
		},
		SecurityHeaders: config.SecurityHeadersConfig{Enabled: true, CSP: "default-src 'none'"},
	}
	eng, err := NewEngine(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer eng.ThreatLogger.Close()
	proxy, err := NewReverseProxy(eng)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ host, want string }{
		{"wifme.id", "default-src 'self'"},
		{"www.wifme.id", "default-src 'self'"},
		{"other.example", "default-src 'none'"},
	} {
		t.Run(tc.host, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "http://"+tc.host+"/", nil)
			proxy.Handler.ServeHTTP(rec, req)
			values := rec.Result().Header.Values("Content-Security-Policy")
			if rec.Code != http.StatusOK || len(values) != 1 || values[0] != tc.want {
				t.Fatalf("status=%d CSP=%v; want 200 and %q", rec.Code, values, tc.want)
			}
		})
	}
}
