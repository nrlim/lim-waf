package dashboard

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"sync/atomic"

	"github.com/nrlim/lim-waf/internal/engine"
)

//go:embed static
var staticFiles embed.FS

// Server represents the dashboard HTTP server.
type Server struct {
	Engine *engine.WAFEngine
	port   int
}

// NewServer creates a new dashboard server bound to localhost.
func NewServer(eng *engine.WAFEngine, port int) *Server {
	return &Server{
		Engine: eng,
		port:   port,
	}
}

// Start runs the dashboard server.
func (s *Server) Start() error {
	mux := http.NewServeMux()

	// Serve static files
	staticFS, err := fs.Sub(staticFiles, "static")
	if err != nil {
		return fmt.Errorf("failed to load static files: %w", err)
	}
	mux.Handle("/", http.FileServer(http.FS(staticFS)))

	// API endpoints
	mux.HandleFunc("/api/stats", s.handleStats)
	mux.HandleFunc("/api/rules/reload", s.handleReload)

	addr := fmt.Sprintf("127.0.0.1:%d", s.port)
	log.Printf("Starting Admin Dashboard on http://%s", addr)
	
	return http.ListenAndServe(addr, mux)
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]uint64{
		"total_requests":   atomic.LoadUint64(&s.Engine.Stats.TotalRequests),
		"blocked_requests": atomic.LoadUint64(&s.Engine.Stats.BlockedRequests),
	})
}

func (s *Server) handleReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Reload engine config
	if err := s.Engine.Reload(s.Engine.Config); err != nil {
		http.Error(w, fmt.Sprintf("Failed to reload WAF: %v", err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"success"}`))
}
