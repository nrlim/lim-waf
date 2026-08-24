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
					if bd.config.VerifyBotsByDNS != nil && *bd.config.VerifyBotsByDNS {
						clientIP := getClientIP(r)
						if !verifySearchBotDNS(clientIP, allowedBot) {
							// User-Agent spoofing attempt detected!
							atomic.AddUint64(&bd.stats.BotDetectedReqs, 1)
							http.Error(w, "Forbidden - Fake Search Engine Crawler", http.StatusForbidden)
							return
						}
					}
					// Legitimate/verified search engine crawler — signal downstream middleware
					// and pass through without header heuristic checks.
					// This header is an internal trust signal; it is stripped before reaching the backend.
					r.Header.Set("X-LIM-Verified-Bot", getBotVendor(strings.ToLower(allowedBot)))
					next.ServeHTTP(w, r)
					return
				}
			}
		}

		// 3. Header Heuristics for Browser Spoofing Protection
		if r.Method == http.MethodGet {
			// Empty UA is suspicious for web traffic
			if ua == "" {
				atomic.AddUint64(&bd.stats.BotDetectedReqs, 1)
				http.Error(w, "Forbidden - Missing User-Agent", http.StatusForbidden)
				return
			}

			// Smart Browser-Spoofing Protection:
			// Detect automated scrapers that claim to be a standard browser (Mozilla...) but fail to send standard Accept headers.
			// Known crawlers, inspection tools, and SDKs are exempted to prevent false positives.
			if strings.Contains(uaLower, "mozilla") && !isKnownToolOrBot(uaLower) {
				accept := r.Header.Get("Accept")
				if accept == "" {
					atomic.AddUint64(&bd.stats.BotDetectedReqs, 1)
					http.Error(w, "Forbidden - Suspicious Browser Request Headers", http.StatusForbidden)
					return
				}
			}
		}

		// Proceed to next middleware
		next.ServeHTTP(w, r)
	})
}

// isKnownToolOrBot checks if User-Agent contains keywords of official tools, crawlers, or SDKs.
// This prevents the browser-spoofing heuristic from incorrectly flagging legitimate Google tools
// (e.g., Google-InspectionTool, Google-Site-Verification) that send Mozilla-prefixed UAs.
func isKnownToolOrBot(ua string) bool {
	botKeywords := []string{
		// Generic crawler signals
		"bot", "crawler", "spider",
		// Google common crawlers
		"googlebot", "google-inspectiontool", "google-site-verification",
		"storebot-google", "google-read-aloud", "google-safety", "google-extended",
		"adsbot-google", "apis-google", "feedfetcher-google", "mediapartners-google",
		// Google diagnostic tools
		"inspection", "lighthouse", "pagespeed",
		// Bing / Microsoft
		"bingbot", "bing",
		// Other search engines
		"yandex", "baidu", "duckduck", "slurp",
		// Social media preview fetchers
		"facebook", "twitter", "whatsapp", "linkedin", "telegram", "discord",
	}
	for _, kw := range botKeywords {
		if strings.Contains(ua, kw) {
			return true
		}
	}
	return false
}

// getBotVendor maps a known bot keyword to a canonical vendor name for the X-LIM-Verified-Bot header.
func getBotVendor(keyword string) string {
	switch {
	case strings.Contains(keyword, "google"):
		return "google"
	case strings.Contains(keyword, "bing"):
		return "bing"
	case strings.Contains(keyword, "yandex"):
		return "yandex"
	case strings.Contains(keyword, "baidu"):
		return "baidu"
	case strings.Contains(keyword, "duckduck"):
		return "duckduckgo"
	default:
		return "other"
	}
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
