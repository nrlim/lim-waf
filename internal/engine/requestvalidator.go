package engine

import (
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/nrlim/lim-waf/internal/config"
)

// RequestValidator provides structural and size validation of HTTP requests.
type RequestValidator struct {
	config *config.RequestValidationConfig
	stats  *WAFStats
}

// NewRequestValidator initializes a new RequestValidator module.
func NewRequestValidator(cfg *config.RequestValidationConfig, stats *WAFStats) *RequestValidator {
	return &RequestValidator{
		config: cfg,
		stats:  stats,
	}
}

func parseSize(s string, defaultVal int64) int64 {
	s = strings.ToUpper(strings.TrimSpace(s))
	multiplier := int64(1)
	if strings.HasSuffix(s, "KB") {
		multiplier = 1024
		s = strings.TrimSuffix(s, "KB")
	} else if strings.HasSuffix(s, "MB") {
		multiplier = 1024 * 1024
		s = strings.TrimSuffix(s, "MB")
	} else if strings.HasSuffix(s, "GB") {
		multiplier = 1024 * 1024 * 1024
		s = strings.TrimSuffix(s, "GB")
	}
	
	val, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return defaultVal
	}
	return val * multiplier
}

func isBlockedExtension(path string, blocked []string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	if ext == "" {
		return false
	}
	for _, b := range blocked {
		if ext == strings.ToLower(b) {
			return true
		}
	}
	return false
}

// Middleware enforces size limits and content rules.
func (rv *RequestValidator) Middleware(next http.Handler) http.Handler {
	if !rv.config.Enabled {
		return next
	}

	maxBodyBytes := parseSize(rv.config.MaxBodySize, 10*1024*1024)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 1. Max URL Length
		if rv.config.MaxURLLength > 0 && len(r.URL.String()) > rv.config.MaxURLLength {
			atomic.AddUint64(&rv.stats.ValidationFailReqs, 1)
			http.Error(w, "URI Too Long", http.StatusRequestURITooLong)
			return
		}

		// 2. Max Body Size (if Content-Length is provided)
		if r.ContentLength > 0 {
			if r.ContentLength > maxBodyBytes {
				atomic.AddUint64(&rv.stats.ValidationFailReqs, 1)
				http.Error(w, "Payload Too Large", http.StatusRequestEntityTooLarge)
				return
			}
		}

		// 3. Blocked Extensions
		ext := strings.ToLower(filepath.Ext(r.URL.Path))
		if ext != "" {
			for _, blockedExt := range rv.config.BlockedExtensions {
				if ext == strings.ToLower(blockedExt) {
					atomic.AddUint64(&rv.stats.ValidationFailReqs, 1)
					http.Error(w, "Forbidden - Extension not allowed", http.StatusForbidden)
					return
				}
			}
		}

		// 4. Header Size Check
		var headerSize int
		for k, vv := range r.Header {
			headerSize += len(k)
			for _, v := range vv {
				headerSize += len(v)
			}
		}
		if rv.config.MaxHeaderSize > 0 && headerSize > rv.config.MaxHeaderSize {
			atomic.AddUint64(&rv.stats.ValidationFailReqs, 1)
			http.Error(w, "Request Header Fields Too Large", http.StatusRequestHeaderFieldsTooLarge)
			return
		}

		// 4. Content Type Check (only if method expects body)
		if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch {
			cType := r.Header.Get("Content-Type")
			allowedType := false
			
			// If AllowedContentTypes is empty, allow all. Otherwise, enforce.
			if len(rv.config.AllowedContentTypes) == 0 {
				allowedType = true
			} else {
				for _, allowed := range rv.config.AllowedContentTypes {
					if strings.HasPrefix(strings.ToLower(cType), strings.ToLower(allowed)) {
						allowedType = true
						break
					}
				}
			}

			if !allowedType && cType != "" {
				atomic.AddUint64(&rv.stats.ValidationFailReqs, 1)
				http.Error(w, "Unsupported Media Type", http.StatusUnsupportedMediaType)
				return
			}
			
			// 5. Enforce max body size early via Content-Length if present
			if r.ContentLength > maxBodyBytes {
				atomic.AddUint64(&rv.stats.ValidationFailReqs, 1)
				http.Error(w, "Payload Too Large", http.StatusRequestEntityTooLarge)
				return
			}
			
			// Wrap body with MaxBytesReader to prevent streaming abuse
			if maxBodyBytes > 0 {
				r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
			}
		}

		// TODO: Deep JSON parsing validation could be added here if needed, 
		// but requires reading and buffering body which WAF does anyway.
		// For now we rely on MaxBodyBytes to prevent huge JSON bombs.

		next.ServeHTTP(w, r)
	})
}
