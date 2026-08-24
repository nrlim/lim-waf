package engine

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/nrlim/lim-waf/internal/config"
)

// ThreatLogEntry represents a structured log format for WAF events.
type ThreatLogEntry struct {
	Timestamp    string `json:"timestamp"`
	ClientIP     string `json:"client_ip"`
	Method       string `json:"method"`
	URI          string `json:"uri"`
	ResponseCode int    `json:"response_code"`
	DurationMs   int64  `json:"duration_ms"`
	Blocked      bool   `json:"blocked"`
	UserAgent    string `json:"user_agent"`
}

// responseWriterWrapper captures the response status code.
type responseWriterWrapper struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriterWrapper) WriteHeader(statusCode int) {
	rw.statusCode = statusCode
	rw.ResponseWriter.WriteHeader(statusCode)
}

func (rw *responseWriterWrapper) Write(b []byte) (int, error) {
	if rw.statusCode == 0 {
		rw.statusCode = http.StatusOK
	}
	return rw.ResponseWriter.Write(b)
}

func (rw *responseWriterWrapper) Flush() {
	if flusher, ok := rw.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

// ThreatLogger logs all requests in a structured format.
type ThreatLogger struct {
	config *config.ThreatLoggingConfig
	logger *log.Logger
	file   *os.File
}

// NewThreatLogger initializes a new ThreatLogger.
func NewThreatLogger(cfg *config.ThreatLoggingConfig) (*ThreatLogger, error) {
	if !cfg.Enabled {
		return &ThreatLogger{config: cfg}, nil
	}

	dir := filepath.Dir(cfg.Output)
	if dir != "" && dir != "." {
		_ = os.MkdirAll(dir, 0755)
	}

	f, err := os.OpenFile(cfg.Output, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}

	return &ThreatLogger{
		config: cfg,
		logger: log.New(f, "", 0), // No standard prefixes, we write raw JSON
		file:   f,
	}, nil
}

// Middleware returns the HTTP handler that logs requests.
func (tl *ThreatLogger) Middleware(next http.Handler) http.Handler {
	if !tl.config.Enabled {
		return next
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rw := &responseWriterWrapper{ResponseWriter: w, statusCode: 0}

		start := time.Now()
		next.ServeHTTP(rw, r)
		duration := time.Since(start)

		if rw.statusCode == 0 {
			rw.statusCode = http.StatusOK
		}

		entry := ThreatLogEntry{
			Timestamp:    start.UTC().Format(time.RFC3339Nano),
			ClientIP:     getClientIP(r),
			Method:       r.Method,
			URI:          r.URL.RequestURI(),
			ResponseCode: rw.statusCode,
			DurationMs:   duration.Milliseconds(),
			Blocked:      rw.statusCode == http.StatusForbidden || rw.statusCode == http.StatusNotAcceptable || rw.statusCode == http.StatusTooManyRequests,
			UserAgent:    r.Header.Get("User-Agent"),
		}

		b, err := json.Marshal(entry)
		if err == nil {
			tl.logger.Println(string(b))
		}
	})
}

// Close closes the log file.
func (tl *ThreatLogger) Close() error {
	if tl.file != nil {
		return tl.file.Close()
	}
	return nil
}
