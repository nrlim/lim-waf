package engine

import (
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
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

// NewReverseProxy creates a new reverse proxy with the WAF engine attached.
func NewReverseProxy(eng *WAFEngine, siteDomain string) (*ReverseProxy, error) {
	if len(eng.Config.Sites) == 0 {
		return nil, fmt.Errorf("no sites configured")
	}
	
	siteCfg := eng.Config.Sites[0]

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
		log.Printf("Proxy error: %v", err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
	}

	var finalHandler http.Handler = proxy

	if siteCfg.WAF.Enabled {
		wafHandler := txhttp.WrapHandler(eng.WAF, proxy)
		// We wrap the coraza handler with our interceptor to catch 403s
		finalHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			iw := &interceptorRW{
				ResponseWriter: w,
				req:            r,
				eng:            eng,
			}
			wafHandler.ServeHTTP(iw, r)
		})
	}

	return &ReverseProxy{
		Handler: finalHandler,
		Engine:  eng,
	}, nil
}

// ServeHTTP implements the http.Handler interface
func (rp *ReverseProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	atomic.AddUint64(&rp.Engine.Stats.TotalRequests, 1)
	rp.Handler.ServeHTTP(w, r)
}
