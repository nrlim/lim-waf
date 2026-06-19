package engine

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nrlim/lim-waf/internal/config"
)

// clientStatus holds the rate limiting state for a single IP.
type clientStatus struct {
	Count      int
	WindowTime time.Time
	BanCount   int
	BannedUntil time.Time
}

// RateLimiter is an HTTP middleware for rate limiting and auto-banning.
type RateLimiter struct {
	config  *config.RateLimitConfig
	stats   *WAFStats
	clients sync.Map
	mu      sync.Mutex // For cleanup
}

// NewRateLimiter initializes a new RateLimiter.
func NewRateLimiter(cfg *config.RateLimitConfig, stats *WAFStats) *RateLimiter {
	rl := &RateLimiter{
		config: cfg,
		stats:  stats,
	}

	// Start cleanup routine
	go rl.cleanupRoutine()

	return rl
}

func (rl *RateLimiter) cleanupRoutine() {
	for {
		time.Sleep(1 * time.Minute)
		now := time.Now()
		rl.clients.Range(func(key, value interface{}) bool {
			status := value.(*clientStatus)
			// Remove if window has passed and not banned
			if now.After(status.WindowTime.Add(time.Minute)) && now.After(status.BannedUntil) {
				rl.clients.Delete(key)
			}
			return true
		})
	}
}

func getClientIP(r *http.Request) string {
	ip := r.Header.Get("X-Forwarded-For")
	if ip != "" {
		parts := strings.Split(ip, ",")
		return strings.TrimSpace(parts[0])
	}
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

func parseDuration(d string, defaultDur time.Duration) time.Duration {
	parsed, err := time.ParseDuration(d)
	if err != nil {
		return defaultDur
	}
	return parsed
}

// Middleware returns the HTTP handler that enforces rate limits.
func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	if !rl.config.Enabled {
		return next
	}

	banDuration := parseDuration(rl.config.BanDuration, 10*time.Minute)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := getClientIP(r)
		now := time.Now()

		// Get or create client status
		val, _ := rl.clients.LoadOrStore(ip, &clientStatus{
			Count:      0,
			WindowTime: now,
		})
		status := val.(*clientStatus)

		rl.mu.Lock()
		// Check if banned
		if now.Before(status.BannedUntil) {
			rl.mu.Unlock()
			atomic.AddUint64(&rl.stats.RateLimitedReqs, 1)
			w.Header().Set("Retry-After", fmt.Sprintf("%.0f", time.Until(status.BannedUntil).Seconds()))
			http.Error(w, "Too Many Requests - IP Banned", http.StatusTooManyRequests)
			return
		}

		// Reset window if a minute has passed
		if now.After(status.WindowTime.Add(time.Minute)) {
			status.Count = 0
			status.WindowTime = now
		}

		status.Count++

		// Determine the limit for this path
		limit := rl.config.RequestsPerMinute
		for _, p := range rl.config.Paths {
			if strings.HasPrefix(r.URL.Path, p.Pattern) {
				limit = p.RequestsPerMinute
				break
			}
		}

		if status.Count > limit+rl.config.Burst {
			status.BanCount++
			atomic.AddUint64(&rl.stats.RateLimitedReqs, 1)
			if rl.config.BanThreshold > 0 && status.BanCount >= rl.config.BanThreshold {
				status.BannedUntil = now.Add(banDuration)
				rl.mu.Unlock()
				w.Header().Set("Retry-After", fmt.Sprintf("%.0f", time.Until(status.BannedUntil).Seconds()))
				http.Error(w, "Too Many Requests - IP Banned", http.StatusTooManyRequests)
				return
			}
			rl.mu.Unlock()
			w.Header().Set("Retry-After", "60")
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}

		remaining := limit - status.Count
		if remaining < 0 {
			remaining = 0
		}
		w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", limit))
		w.Header().Set("X-RateLimit-Remaining", fmt.Sprintf("%d", remaining))
		rl.mu.Unlock()

		next.ServeHTTP(w, r)
	})
}
