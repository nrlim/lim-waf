package engine

import (
	"net"
	"net/http"
	"strings"
	"sync/atomic"

	"github.com/nrlim/lim-waf/internal/config"
)

// BotDetection provides heuristics-based bot blocking and search engine bot whitelisting.
type BotDetection struct {
	config *config.BotDetectionConfig
	stats  *WAFStats
}

// NewBotDetection initializes a new BotDetection module.
func NewBotDetection(cfg *config.BotDetectionConfig, stats *WAFStats) *BotDetection {
	return &BotDetection{
		config: cfg,
		stats:  stats,
	}
}

// Middleware returns the HTTP handler that performs bot detection and whitelisting.
func (bd *BotDetection) Middleware(next http.Handler) http.Handler {
	if !bd.config.Enabled {
		return next
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 1. Honeypot check: No bot (even crawlers) should access honeypot paths
		for _, hp := range bd.config.HoneypotPaths {
			if strings.HasPrefix(r.URL.Path, hp) {
				atomic.AddUint64(&bd.stats.BotDetectedReqs, 1)
				http.Error(w, "Forbidden - Malicious Bot Detected", http.StatusForbidden)
				return
			}
		}

		ua := r.Header.Get("User-Agent")
		uaLower := strings.ToLower(ua)

		// 2. Search Engine Crawler Whitelisting (Google, Bing, Yahoo, DuckDuckGo, Baidu, Yandex, etc.)
		if uaLower != "" {
			for _, allowedBot := range bd.config.AllowedBots {
				if strings.Contains(uaLower, strings.ToLower(allowedBot)) {
					// Found matching whitelisted bot UA pattern
					if bd.config.VerifyBotsByDNS {
						clientIP := getClientIP(r)
						if !verifySearchBotDNS(clientIP, allowedBot) {
							// User-Agent spoofing attempt detected!
							atomic.AddUint64(&bd.stats.BotDetectedReqs, 1)
							http.Error(w, "Forbidden - Fake Search Engine Crawler", http.StatusForbidden)
							return
						}
					}
					// Legitimate/verified search engine crawler — pass through without header heuristic checks
					next.ServeHTTP(w, r)
					return
				}
			}
		}

		// 3. Header Heuristics for General Browsers
		if r.Method == http.MethodGet {
			accept := r.Header.Get("Accept")
			acceptLang := r.Header.Get("Accept-Language")

			// Empty UA is suspicious for web traffic
			if ua == "" {
				atomic.AddUint64(&bd.stats.BotDetectedReqs, 1)
				http.Error(w, "Forbidden - Missing User-Agent", http.StatusForbidden)
				return
			}

			// Simple heuristic: If UA claims to be a standard browser (Mozilla...) but lacks basic headers
			if strings.Contains(uaLower, "mozilla") {
				if accept == "" || acceptLang == "" {
					atomic.AddUint64(&bd.stats.BotDetectedReqs, 1)
					http.Error(w, "Forbidden - Suspicious Request Headers", http.StatusForbidden)
					return
				}
			}
		}

		// Proceed to next middleware
		next.ServeHTTP(w, r)
	})
}

// verifySearchBotDNS performs Forward-Confirmed Reverse DNS (FCrDNS) lookup
// to verify if an incoming IP address genuinely belongs to a search engine bot.
func verifySearchBotDNS(ipStr string, botKeyword string) bool {
	names, err := net.LookupAddr(ipStr)
	if err != nil || len(names) == 0 {
		return false
	}

	botKeywordLower := strings.ToLower(botKeyword)

	// Validate reverse hostname belongs to official search engine domains
	validHost := false
	var matchedHost string
	for _, name := range names {
		host := strings.TrimSuffix(strings.ToLower(name), ".")
		if isOfficialBotDomain(host, botKeywordLower) {
			validHost = true
			matchedHost = host
			break
		}
	}

	if !validHost {
		return false
	}

	// Forward lookup: ensure hostname resolves back to the original IP
	addrs, err := net.LookupHost(matchedHost)
	if err != nil {
		return false
	}

	for _, addr := range addrs {
		if addr == ipStr {
			return true
		}
	}

	return false
}

// isOfficialBotDomain checks if hostname matches official search engine domain suffixes.
func isOfficialBotDomain(host string, botKeyword string) bool {
	switch {
	case strings.Contains(botKeyword, "google"):
		return strings.HasSuffix(host, ".googlebot.com") || strings.HasSuffix(host, ".google.com")
	case strings.Contains(botKeyword, "bing"):
		return strings.HasSuffix(host, ".search.msn.com") || strings.HasSuffix(host, ".bing.com")
	case strings.Contains(botKeyword, "yandex"):
		return strings.HasSuffix(host, ".yandex.com") || strings.HasSuffix(host, ".yandex.ru") || strings.HasSuffix(host, ".yandex.net")
	case strings.Contains(botKeyword, "baidu"):
		return strings.HasSuffix(host, ".baidu.com") || strings.HasSuffix(host, ".baidu.jp")
	case strings.Contains(botKeyword, "duckduck"):
		return strings.HasSuffix(host, ".duckduckgo.com")
	default:
		return strings.Contains(host, botKeyword)
	}
}
