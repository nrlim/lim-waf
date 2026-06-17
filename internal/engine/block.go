package engine

import (
	"bytes"
	_ "embed"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"time"

	"github.com/nrlim/lim-waf/internal/config"
)

//go:embed templates/block.html
var blockPageTemplate string

// BlockPageData holds data to be injected into the block page template.
type BlockPageData struct {
	TransactionID string
	ClientIP      string
	Timestamp     string
	BrandingName  string
	BrandingURL   string
}

// BlockErrorHandler returns an http.Handler that renders the branded block page.
func BlockErrorHandler(cfg *config.Config) func(http.ResponseWriter, *http.Request, error) {
	tmpl, err := template.New("block").Parse(blockPageTemplate)
	if err != nil {
		log.Fatalf("failed to parse block page template: %v", err)
	}

	return func(w http.ResponseWriter, r *http.Request, err error) {
		// In a typical Coraza setup, the transaction ID might be available
		// in the request context or custom headers. If not, we generate a simple one
		// or extract from Coraza context if possible.
		txID := r.Header.Get("X-Coraza-TxId")
		if txID == "" {
			txID = fmt.Sprintf("%d", time.Now().UnixNano())
		}

		clientIP := r.RemoteAddr
		// Basic reverse proxy IP extraction (if behind another proxy)
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			clientIP = xff
		}

		data := BlockPageData{
			TransactionID: txID,
			ClientIP:      clientIP,
			Timestamp:     time.Now().UTC().Format(time.RFC3339),
			BrandingName:  cfg.Branding.Name,
			BrandingURL:   cfg.Branding.URL,
		}

		var buf bytes.Buffer
		if err := tmpl.Execute(&buf, data); err != nil {
			http.Error(w, "Access Denied", http.StatusForbidden)
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusForbidden)
		w.Write(buf.Bytes())
	}
}
