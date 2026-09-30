package engine

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/nrlim/lim-waf/internal/config"
)

// SecurityHeaders applies security and CORS headers to HTTP responses.
type SecurityHeaders struct {
	config *config.SecurityHeadersConfig
}

// NewSecurityHeaders initializes the SecurityHeaders middleware.
func NewSecurityHeaders(cfg *config.SecurityHeadersConfig) *SecurityHeaders {
	return &SecurityHeaders{
		config: cfg,
	}
}

// Middleware returns the HTTP handler that applies security headers.
func (sh *SecurityHeaders) Middleware(next http.Handler) http.Handler {
	if !sh.config.Enabled {
		return next
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Apply CSP at response commit so upstream headers cannot duplicate the policy.
		sw := &secHeaderWriter{ResponseWriter: w, sh: sh, r: r, headerWritten: false}
		if sh.config.CORS.Enabled && r.Method == http.MethodOptions {
			if sh.handleCORS(sw, r) {
				sw.WriteHeader(http.StatusNoContent)
				return
			}
		}
		next.ServeHTTP(sw, r)
		if !sw.headerWritten {
			sw.WriteHeader(http.StatusOK)
		}
	})
}

// secHeaderWriter replaces upstream CSP and fills other missing security headers.
type secHeaderWriter struct {
	http.ResponseWriter
	sh            *SecurityHeaders
	r             *http.Request
	headerWritten bool
}

func (sw *secHeaderWriter) WriteHeader(statusCode int) {
	if statusCode >= 100 && statusCode < 200 {
		sw.ResponseWriter.WriteHeader(statusCode)
		return
	}
	if sw.headerWritten {
		return
	}
	sw.headerWritten = true
	sw.applyHeaders()
	sw.ResponseWriter.WriteHeader(statusCode)
}

func (sw *secHeaderWriter) Write(b []byte) (int, error) {
	if !sw.headerWritten {
		sw.headerWritten = true
		sw.applyHeaders()
	}
	return sw.ResponseWriter.Write(b)
}

func (sw *secHeaderWriter) Flush() {
	if !sw.headerWritten {
		sw.WriteHeader(http.StatusOK)
	}
	if flusher, ok := sw.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

// setIfAbsent sets a response header only if the upstream backend didn't already provide it.
func (sw *secHeaderWriter) setIfAbsent(key, value string) {
	if sw.Header().Get(key) == "" {
		sw.Header().Set(key, value)
	}
}

func (sw *secHeaderWriter) applyHeaders() {
	sw.setIfAbsent("X-Content-Type-Options", "nosniff")
	sw.setIfAbsent("X-XSS-Protection", "1; mode=block")
	sw.setIfAbsent("X-Permitted-Cross-Domain-Policies", "none")

	if sw.sh.config.FrameOptions != "" {
		sw.setIfAbsent("X-Frame-Options", sw.sh.config.FrameOptions)
	}

	if sw.sh.config.CSP != "" {
		policy := sw.sh.config.CSP
		// Preserve the application's stricter sandbox for private document responses.
		for _, upstream := range sw.Header().Values("Content-Security-Policy") {
			if upstream == "default-src 'none'; style-src 'unsafe-inline'; script-src 'none'; base-uri 'none'; form-action 'none'" {
				policy = upstream // Firewall block pages have a stricter, self-contained policy.
				break
			}
			if strings.TrimSpace(upstream) == "sandbox" {
				policy += "; sandbox"
				break
			}
		}
		sw.Header().Set("Content-Security-Policy", policy)
	}

	if sw.sh.config.ReferrerPolicy != "" {
		sw.setIfAbsent("Referrer-Policy", sw.sh.config.ReferrerPolicy)
	}

	if sw.sh.config.HSTS {
		sw.setIfAbsent("Strict-Transport-Security", fmt.Sprintf("max-age=%d; includeSubDomains", sw.sh.config.HSTSMaxAge))
	}

	// Also apply CORS to normal responses
	if sw.sh.config.CORS.Enabled {
		sw.sh.handleCORS(sw.ResponseWriter, sw.r)
	}
}

// handleCORS sets CORS headers and returns true if it's a valid preflight request.
func (sh *SecurityHeaders) handleCORS(w http.ResponseWriter, r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return false
	}

	allowedOrigin := ""
	if len(sh.config.CORS.AllowedOrigins) == 1 && sh.config.CORS.AllowedOrigins[0] == "*" {
		allowedOrigin = "*"
	} else {
		for _, o := range sh.config.CORS.AllowedOrigins {
			if o == origin {
				allowedOrigin = origin
				break
			}
		}
	}

	if allowedOrigin == "" {
		return false
	}

	w.Header().Set("Access-Control-Allow-Origin", allowedOrigin)

	if sh.config.CORS.AllowCredentials {
		w.Header().Set("Access-Control-Allow-Credentials", "true")
	}

	if len(sh.config.CORS.ExposedHeaders) > 0 {
		w.Header().Set("Access-Control-Expose-Headers", strings.Join(sh.config.CORS.ExposedHeaders, ", "))
	}

	// For preflight
	if r.Method == http.MethodOptions {
		if len(sh.config.CORS.AllowedMethods) > 0 {
			w.Header().Set("Access-Control-Allow-Methods", strings.Join(sh.config.CORS.AllowedMethods, ", "))
		}
		if len(sh.config.CORS.AllowedHeaders) > 0 {
			w.Header().Set("Access-Control-Allow-Headers", strings.Join(sh.config.CORS.AllowedHeaders, ", "))
		}
		if sh.config.CORS.MaxAge > 0 {
			w.Header().Set("Access-Control-Max-Age", fmt.Sprintf("%d", sh.config.CORS.MaxAge))
		}
		return true
	}

	return false
}
