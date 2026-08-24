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
		// Handle CORS Preflight
		if sh.config.CORS.Enabled && r.Method == http.MethodOptions {
			if sh.handleCORS(w, r) {
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}

		// Use a wrapper that defers header writing until the upstream response is received,
		// so we can check what the backend already set and avoid overwriting.
		sw := &secHeaderWriter{ResponseWriter: w, sh: sh, r: r, headerWritten: false}
		next.ServeHTTP(sw, r)
	})
}

// secHeaderWriter intercepts WriteHeader to inject security headers only if
// the upstream backend (Next.js) hasn't already set them.
type secHeaderWriter struct {
	http.ResponseWriter
	sh            *SecurityHeaders
	r             *http.Request
	headerWritten bool
}

func (sw *secHeaderWriter) WriteHeader(statusCode int) {
	if !sw.headerWritten {
		sw.headerWritten = true
		sw.applyHeaders()
	}
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
		sw.setIfAbsent("Content-Security-Policy", sw.sh.config.CSP)
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
