package engine

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nrlim/lim-waf/internal/config"
)

func TestSecurityHeadersCSP(t *testing.T) {
	for _, tc := range []struct {
		name     string
		upstream string
		flush    bool
		empty    bool
		want     string
	}{
		{name: "replace upstream", upstream: "default-src https: 'unsafe-eval'", want: "default-src 'self'"},
		{name: "preserve document sandbox", upstream: "sandbox", want: "default-src 'self'; sandbox"},
		{name: "stream flush", flush: true, want: "default-src 'self'"},
		{name: "empty response", empty: true, want: "default-src 'self'"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sh := NewSecurityHeaders(&config.SecurityHeadersConfig{Enabled: true, CSP: "default-src 'self'"})
			rec := httptest.NewRecorder()
			sh.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.upstream != "" {
					w.Header().Add("Content-Security-Policy", tc.upstream)
					w.Header().Add("Content-Security-Policy", tc.upstream)
				}
				if tc.flush {
					w.(http.Flusher).Flush()
					return
				}
				if !tc.empty {
					w.WriteHeader(http.StatusForbidden)
				}
			})).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
			values := rec.Result().Header.Values("Content-Security-Policy")
			if len(values) != 1 || values[0] != tc.want {
				t.Fatalf("CSP = %v; want exactly %q", values, tc.want)
			}
		})
	}
}
