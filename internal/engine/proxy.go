package engine

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	txhttp "github.com/corazawaf/coraza/v3/http"
)

// ReverseProxy wrap the original httputil.ReverseProxy and adds Coraza WAF middleware
type ReverseProxy struct {
	Handler http.Handler
	Engine  *WAFEngine
}

// interceptorRW catches the HTTP status written by Coraza WrapHandler.
// If it's a block (e.g., 403), we can render our custom block page instead.
type interceptorRW struct {
	http.ResponseWriter
	req        *http.Request
	eng        *WAFEngine
	statusCode int
	wroteBlock bool
}

func (i *interceptorRW) WriteHeader(statusCode int) {
	if statusCode == http.StatusForbidden || statusCode == http.StatusNotAcceptable {
		i.statusCode = statusCode
		i.wroteBlock = true
		// Do not write header yet, we will write our own block page
		atomic.AddUint64(&i.eng.Stats.BlockedRequests, 1)
		BlockErrorHandler(i.eng.Config)(i.ResponseWriter, i.req, nil)
		return
	}
	i.statusCode = statusCode
	i.ResponseWriter.WriteHeader(statusCode)
}

func (i *interceptorRW) Write(b []byte) (int, error) {
	if i.wroteBlock {
		// Ignore writing default coraza response body if we already rendered our block page
		return len(b), nil
	}
	return i.ResponseWriter.Write(b)
}

// NewReverseProxy creates a new reverse proxy that routes based on the domain.
func NewReverseProxy(eng *WAFEngine) (*ReverseProxy, error) {
	if len(eng.Config.Sites) == 0 {
		return nil, fmt.Errorf("no sites configured")
	}

	proxies := make(map[string]http.Handler)

	for _, siteCfg := range eng.Config.Sites {
		targetURL, err := url.Parse(siteCfg.Backend)
		if err != nil {
			return nil, fmt.Errorf("invalid backend URL '%s': %w", siteCfg.Backend, err)
		}

		proxy := httputil.NewSingleHostReverseProxy(targetURL)

		proxy.Transport = &http.Transport{
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		}

		proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("Proxy error for %s: %v", siteCfg.Domain, err)
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
		}

		var finalHandler http.Handler = proxy

		if siteCfg.WAF.Enabled {
			// Base WAF handler
			wafHandler := txhttp.WrapHandler(eng.WAF, proxy)
			finalHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				iw := &interceptorRW{
					ResponseWriter: w,
					req:            r,
					eng:            eng,
				}
				wafHandler.ServeHTTP(iw, r)
			})
		}

		// Apply middlewares (Outermost to innermost)
		// Chain: ThreatLogger -> RateLimiter -> IPReputation -> BotDetection -> RequestValidator -> SecurityHeaders -> WAF -> Proxy
		finalHandler = eng.SecurityHeaders.Middleware(finalHandler)
		finalHandler = eng.RequestValidator.Middleware(finalHandler)
		finalHandler = eng.BotDetection.Middleware(finalHandler)
		finalHandler = eng.IPReputation.Middleware(finalHandler)
		finalHandler = eng.RateLimiter.Middleware(finalHandler)
		finalHandler = eng.ThreatLogger.Middleware(finalHandler)

		domain := strings.ToLower(siteCfg.Domain)
		proxies[domain] = finalHandler
		if !strings.HasPrefix(domain, "www.") {
			proxies["www."+domain] = finalHandler
		}
	}

	masterHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := strings.ToLower(r.Host)
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}

		if handler, ok := proxies[host]; ok {
			handler.ServeHTTP(w, r)
		} else {
			// Fallback to the first site if host doesn't match
			firstSiteDomain := strings.ToLower(eng.Config.Sites[0].Domain)
			proxies[firstSiteDomain].ServeHTTP(w, r)
		}
	})

	return &ReverseProxy{
		Handler: masterHandler,
		Engine:  eng,
	}, nil
}

// ServeHTTP implements the http.Handler interface
func (rp *ReverseProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	atomic.AddUint64(&rp.Engine.Stats.TotalRequests, 1)
	rp.Handler.ServeHTTP(w, r)
}
