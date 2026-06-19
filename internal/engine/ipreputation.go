package engine

import (
	"log"
	"net"
	"net/http"
	"sync"
	"sync/atomic"

	"github.com/nrlim/lim-waf/internal/config"
)

// IPReputation enforces whitelist and blacklist rules.
type IPReputation struct {
	config    *config.IPReputationConfig
	stats     *WAFStats
	whitelist []*net.IPNet
	blacklist []*net.IPNet
	mu        sync.RWMutex
}

// NewIPReputation initializes a new IPReputation module.
func NewIPReputation(cfg *config.IPReputationConfig, stats *WAFStats) *IPReputation {
	ipr := &IPReputation{
		config: cfg,
		stats:  stats,
	}
	ipr.Reload(cfg)
	return ipr
}

// Reload parses the configured lists into usable CIDR blocks.
func (ipr *IPReputation) Reload(cfg *config.IPReputationConfig) {
	ipr.mu.Lock()
	defer ipr.mu.Unlock()

	ipr.config = cfg
	ipr.whitelist = parseCIDRList(cfg.Whitelist)
	ipr.blacklist = parseCIDRList(cfg.Blacklist)
}

// parseCIDRList converts a list of IP strings/CIDRs to parsed IPNets.
func parseCIDRList(ips []string) []*net.IPNet {
	var nets []*net.IPNet
	for _, ipStr := range ips {
		// If it's just an IP without CIDR notation, add /32 or /128
		if net.ParseIP(ipStr) != nil {
			if stringsContainsColon(ipStr) {
				ipStr += "/128"
			} else {
				ipStr += "/32"
			}
		}

		_, ipNet, err := net.ParseCIDR(ipStr)
		if err == nil {
			nets = append(nets, ipNet)
		} else {
			log.Printf("Warning: invalid IP/CIDR in reputation config: %s", ipStr)
		}
	}
	return nets
}

func stringsContainsColon(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == ':' {
			return true
		}
	}
	return false
}

// IsWhitelisted checks if an IP is explicitly allowed.
func (ipr *IPReputation) IsWhitelisted(ip net.IP) bool {
	ipr.mu.RLock()
	defer ipr.mu.RUnlock()
	for _, network := range ipr.whitelist {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// IsBlacklisted checks if an IP is explicitly blocked.
func (ipr *IPReputation) IsBlacklisted(ip net.IP) bool {
	ipr.mu.RLock()
	defer ipr.mu.RUnlock()
	for _, network := range ipr.blacklist {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// Middleware returns the HTTP handler that enforces IP reputation.
func (ipr *IPReputation) Middleware(next http.Handler) http.Handler {
	if !ipr.config.Enabled {
		return next
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ipStr := getClientIP(r)
		parsedIP := net.ParseIP(ipStr)

		if parsedIP == nil {
			// Malformed IP
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		if ipr.IsWhitelisted(parsedIP) {
			// Skip other checks, but we still proceed to next handler (e.g. WAF)
			next.ServeHTTP(w, r)
			return
		}

		if ipr.IsBlacklisted(parsedIP) {
			atomic.AddUint64(&ipr.stats.IPBlockedReqs, 1)
			http.Error(w, "Forbidden - IP is blocked", http.StatusForbidden)
			return
		}

		// Proceed
		next.ServeHTTP(w, r)
	})
}
