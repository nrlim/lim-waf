package dashboard

import (
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"

	"github.com/nrlim/lim-waf/internal/config"
	"github.com/nrlim/lim-waf/internal/engine"
)

//go:embed static
var staticFiles embed.FS

// loginAttempt tracks failed dashboard logins
type loginAttempt struct {
	Count int
	Last  time.Time
}

// Server represents the dashboard HTTP server.
type Server struct {
	Engine        *engine.WAFEngine
	configPath    string
	loginAttempts sync.Map
}

// NewServer creates a new dashboard server.
func NewServer(eng *engine.WAFEngine, configPath string) *Server {
	return &Server{
		Engine:     eng,
		configPath: configPath,
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

// basicAuth middleware protects routes with Basic Authentication & Rate Limiting.
func (s *Server) basicAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authConfig := s.Engine.Config.Dashboard.BasicAuth
		if authConfig.Username == "" && authConfig.Password == "" {
			next.ServeHTTP(w, r)
			return
		}

		ip := getClientIP(r)
		now := time.Now()

		// Rate Limiting (10 attempts per 10 minutes)
		val, _ := s.loginAttempts.LoadOrStore(ip, &loginAttempt{Count: 0, Last: now})
		attempt := val.(*loginAttempt)

		if attempt.Count >= 10 {
			if now.Sub(attempt.Last) < 10*time.Minute {
				http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
				return
			}
			// Reset if 10 mins passed
			attempt.Count = 0
		}
		attempt.Last = now

		user, pass, ok := r.BasicAuth()
		if !ok || subtle.ConstantTimeCompare([]byte(user), []byte(authConfig.Username)) != 1 {
			attempt.Count++
			w.Header().Set("WWW-Authenticate", `Basic realm="LIM WAF Dashboard"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Bcrypt password check
		err := bcrypt.CompareHashAndPassword([]byte(authConfig.Password), []byte(pass))
		if err != nil {
			attempt.Count++
			w.Header().Set("WWW-Authenticate", `Basic realm="LIM WAF Dashboard"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Reset attempts on success
		s.loginAttempts.Delete(ip)

		// Set CSRF Cookie if not present
		_, err = r.Cookie("X-CSRF-Token")
		if err != nil {
			b := make([]byte, 32)
			rand.Read(b)
			token := hex.EncodeToString(b)
			http.SetCookie(w, &http.Cookie{
				Name:     "X-CSRF-Token",
				Value:    token,
				Path:     "/",
				HttpOnly: false, // Needs to be read by JS
				SameSite: http.SameSiteStrictMode,
			})
		}

		next.ServeHTTP(w, r)
	})
}

// csrfMiddleware validates CSRF tokens on POST requests
func (s *Server) csrfMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			cookie, err := r.Cookie("X-CSRF-Token")
			if err != nil {
				http.Error(w, "Missing CSRF Cookie", http.StatusForbidden)
				return
			}
			headerToken := r.Header.Get("X-CSRF-Token")
			if headerToken == "" || subtle.ConstantTimeCompare([]byte(headerToken), []byte(cookie.Value)) != 1 {
				http.Error(w, "Invalid CSRF Token", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// secureHeaders adds general security headers
func (s *Server) secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

// Start runs the dashboard server.
func (s *Server) Start() error {
	if !s.Engine.Config.Dashboard.Enabled {
		log.Println("Dashboard is disabled in config.")
		return nil
	}

	// Auto-hash password if plaintext
	authConfig := s.Engine.Config.Dashboard.BasicAuth
	if authConfig.Password != "" && !strings.HasPrefix(authConfig.Password, "$2a$") && !strings.HasPrefix(authConfig.Password, "$2b$") {
		log.Println("Dashboard: Plaintext password detected. Auto-hashing and saving to config...")
		hash, err := bcrypt.GenerateFromPassword([]byte(authConfig.Password), bcrypt.DefaultCost)
		if err != nil {
			return fmt.Errorf("failed to hash password: %w", err)
		}
		s.Engine.Config.Dashboard.BasicAuth.Password = string(hash)
		
		// Write back
		data, err := yaml.Marshal(s.Engine.Config)
		if err == nil {
			os.WriteFile(s.configPath, data, 0644)
			log.Println("Dashboard: Password successfully hashed and saved.")
		} else {
			log.Printf("Dashboard: Failed to save hashed password to config: %v", err)
		}
	}

	mux := http.NewServeMux()

	// Serve static files
	staticFS, err := fs.Sub(staticFiles, "static")
	if err != nil {
		return fmt.Errorf("failed to load static files: %w", err)
	}
	mux.Handle("/", http.FileServer(http.FS(staticFS)))

	// API endpoints
	mux.HandleFunc("/api/stats", s.handleStats)
	mux.HandleFunc("/api/stats/modules", s.handleModuleStats)
	mux.HandleFunc("/api/rules/reload", s.handleReload)
	mux.HandleFunc("/api/threats", s.handleThreats)
	
	// Config management
	mux.HandleFunc("/api/config", s.handleGetConfig)
	mux.HandleFunc("/api/config/update", s.handleUpdateConfig)

	// IP Management
	mux.HandleFunc("/api/blacklist", s.handleBlacklist)
	mux.HandleFunc("/api/blacklist/add", s.handleAddBlacklist)
	mux.HandleFunc("/api/blacklist/remove", s.handleRemoveBlacklist)
	mux.HandleFunc("/api/whitelist", s.handleWhitelist)
	mux.HandleFunc("/api/whitelist/add", s.handleAddWhitelist)
	mux.HandleFunc("/api/whitelist/remove", s.handleRemoveWhitelist)

	addr := s.Engine.Config.Dashboard.Listen
	if addr == "" {
		addr = ":9443"
	}

	log.Printf("Starting Admin Dashboard on http://%s", addr)
	
	// Wrap with security layers
	handler := s.secureHeaders(s.basicAuth(s.csrfMiddleware(mux)))
	
	return http.ListenAndServe(addr, handler)
}

// --- Dashboard Handlers ---

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	uptime := time.Since(s.Engine.Stats.StartTime).Seconds()

	json.NewEncoder(w).Encode(map[string]interface{}{
		"total_requests":       atomic.LoadUint64(&s.Engine.Stats.TotalRequests),
		"blocked_requests":     atomic.LoadUint64(&s.Engine.Stats.BlockedRequests),
		"rate_limited_reqs":    atomic.LoadUint64(&s.Engine.Stats.RateLimitedReqs),
		"bot_detected_reqs":    atomic.LoadUint64(&s.Engine.Stats.BotDetectedReqs),
		"ip_blocked_reqs":      atomic.LoadUint64(&s.Engine.Stats.IPBlockedReqs),
		"validation_fail_reqs": atomic.LoadUint64(&s.Engine.Stats.ValidationFailReqs),
		"uptime_seconds":       uptime,
	})
}

func (s *Server) handleModuleStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"waf":                s.Engine.Config.Sites[0].WAF.Enabled,
		"rate_limit":         s.Engine.Config.RateLimit.Enabled,
		"ip_reputation":      s.Engine.Config.IPReputation.Enabled,
		"bot_detection":      s.Engine.Config.BotDetection.Enabled,
		"request_validation": s.Engine.Config.RequestValidation.Enabled,
		"security_headers":   s.Engine.Config.SecurityHeaders.Enabled,
	})
}

func (s *Server) handleReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := s.Engine.Reload(s.Engine.Config); err != nil {
		http.Error(w, fmt.Sprintf("Failed to reload WAF: %v", err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"success"}`))
}

func (s *Server) handleThreats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	if !s.Engine.Config.ThreatLogging.Enabled {
		w.Write([]byte(`{"error":"Threat logging is disabled"}`))
		return
	}

	file, err := os.Open(s.Engine.Config.ThreatLogging.Output)
	if err != nil {
		w.Write([]byte(`[]`))
		return
	}
	defer file.Close()

	stat, _ := file.Stat()
	size := stat.Size()
	
	readSize := int64(128 * 1024)
	if size < readSize {
		readSize = size
	}
	
	buf := make([]byte, readSize)
	file.ReadAt(buf, size-readSize)
	
	lines := strings.Split(string(buf), "\n")
	
	var logs []map[string]interface{}
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var entry map[string]interface{}
		if err := json.Unmarshal([]byte(line), &entry); err == nil {
			logs = append(logs, entry)
		}
	}
	
	startIdx := 0
	if len(logs) > 100 {
		startIdx = len(logs) - 100
	}
	
	var reversed []map[string]interface{}
	for i := len(logs) - 1; i >= startIdx; i-- {
		reversed = append(reversed, logs[i])
	}
	
	json.NewEncoder(w).Encode(reversed)
}

func (s *Server) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.Engine.Config)
}

func (s *Server) handleUpdateConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var newCfg config.Config
	if err := json.NewDecoder(r.Body).Decode(&newCfg); err != nil {
		http.Error(w, "Invalid config JSON", http.StatusBadRequest)
		return
	}
	
	// Ensure we preserve the hashed password if not explicitly modified
	if newCfg.Dashboard.BasicAuth.Password == "" || !strings.HasPrefix(newCfg.Dashboard.BasicAuth.Password, "$2a$") {
		// If password is plain text, hash it
		if newCfg.Dashboard.BasicAuth.Password != "" {
			hash, err := bcrypt.GenerateFromPassword([]byte(newCfg.Dashboard.BasicAuth.Password), bcrypt.DefaultCost)
			if err == nil {
				newCfg.Dashboard.BasicAuth.Password = string(hash)
			}
		} else {
			// keep old
			newCfg.Dashboard.BasicAuth.Password = s.Engine.Config.Dashboard.BasicAuth.Password
		}
	}

	data, err := yaml.Marshal(&newCfg)
	if err != nil {
		http.Error(w, "Failed to marshal config", http.StatusInternalServerError)
		return
	}

	if err := os.WriteFile(s.configPath, data, 0644); err != nil {
		http.Error(w, "Failed to write config file", http.StatusInternalServerError)
		return
	}

	if err := s.Engine.Reload(&newCfg); err != nil {
		http.Error(w, fmt.Sprintf("Saved but failed to reload WAF: %v", err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"success"}`))
}

func (s *Server) handleBlacklist(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.Engine.Config.IPReputation.Blacklist)
}

func (s *Server) handleAddBlacklist(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, _ := io.ReadAll(r.Body)
	ipStr := strings.TrimSpace(string(body))
	if net.ParseIP(ipStr) == nil && !strings.Contains(ipStr, "/") {
		http.Error(w, "Invalid IP or CIDR", http.StatusBadRequest)
		return
	}

	cfg := s.Engine.Config
	cfg.IPReputation.Blacklist = append(cfg.IPReputation.Blacklist, ipStr)
	s.saveAndReload(cfg, w)
}

func (s *Server) handleRemoveBlacklist(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, _ := io.ReadAll(r.Body)
	ipStr := strings.TrimSpace(string(body))
	
	cfg := s.Engine.Config
	var newList []string
	for _, ip := range cfg.IPReputation.Blacklist {
		if ip != ipStr {
			newList = append(newList, ip)
		}
	}
	cfg.IPReputation.Blacklist = newList
	s.saveAndReload(cfg, w)
}

func (s *Server) handleWhitelist(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.Engine.Config.IPReputation.Whitelist)
}

func (s *Server) handleAddWhitelist(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, _ := io.ReadAll(r.Body)
	ipStr := strings.TrimSpace(string(body))
	if net.ParseIP(ipStr) == nil && !strings.Contains(ipStr, "/") {
		http.Error(w, "Invalid IP or CIDR", http.StatusBadRequest)
		return
	}

	cfg := s.Engine.Config
	cfg.IPReputation.Whitelist = append(cfg.IPReputation.Whitelist, ipStr)
	s.saveAndReload(cfg, w)
}

func (s *Server) handleRemoveWhitelist(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, _ := io.ReadAll(r.Body)
	ipStr := strings.TrimSpace(string(body))
	
	cfg := s.Engine.Config
	var newList []string
	for _, ip := range cfg.IPReputation.Whitelist {
		if ip != ipStr {
			newList = append(newList, ip)
		}
	}
	cfg.IPReputation.Whitelist = newList
	s.saveAndReload(cfg, w)
}

func (s *Server) saveAndReload(cfg *config.Config, w http.ResponseWriter) {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		http.Error(w, "Failed to marshal config", http.StatusInternalServerError)
		return
	}
	if err := os.WriteFile(s.configPath, data, 0644); err != nil {
		http.Error(w, "Failed to write config", http.StatusInternalServerError)
		return
	}
	if err := s.Engine.Reload(cfg); err != nil {
		http.Error(w, "Failed to reload engine", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"success"}`))
}
