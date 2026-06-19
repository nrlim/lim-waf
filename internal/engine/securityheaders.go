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

		// Set Security Headers
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("X-Permitted-Cross-Domain-Policies", "none")

		if sh.config.FrameOptions != "" {
			w.Header().Set("X-Frame-Options", sh.config.FrameOptions)
		}

		if sh.config.CSP != "" {
			w.Header().Set("Content-Security-Policy", sh.config.CSP)
		}

		if sh.config.ReferrerPolicy != "" {
			w.Header().Set("Referrer-Policy", sh.config.ReferrerPolicy)
		}

		if sh.config.HSTS {
			w.Header().Set("Strict-Transport-Security", fmt.Sprintf("max-age=%d; includeSubDomains", sh.config.HSTSMaxAge))
		}

		// Also apply CORS to normal responses
		if sh.config.CORS.Enabled {
			sh.handleCORS(w, r)
		}

		next.ServeHTTP(w, r)
	})
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
