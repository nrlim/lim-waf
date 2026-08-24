# LIM WAF - AI Agent Context & Guideline

## 1. Project Overview & Identity
**LIM WAF** is a lightweight, custom-branded Web Application Firewall (WAF) and reverse proxy built in Go 1.25. It uses **Coraza WAF v3 (v3.7.0)** as its underlying security engine with OWASP Core Rule Set (CRS) v4 compatibility.

- **Primary Repository Target**: VPS deployments (standalone binary or systemd service).
- **Architecture Topology**: Internet ➜ Upstream Proxy/Nginx (TLS Termination) ➜ LIM WAF (`:80` or `:8081`) ➜ Upstream Backend Services.
- **Admin Dashboard**: Embedded web UI on port `:9443` (or configurable) with Basic Auth and CSRF protection.

---

## 2. Directory Structure & Code Map

```
lim-waf/
├── cmd/
│   └── lim-waf/
│       └── main.go           # Entry point, Cobra CLI (serve, version commands)
├── internal/
│   ├── config/
│   │   └── config.go         # Config schema parsing (YAML), defaults initialization
│   ├── dashboard/
│   │   ├── dashboard.go      # Embedded Admin UI REST API & static file server
│   │   └── static/
│   │       └── index.html    # Single-page dashboard interface
│   └── engine/
│       ├── engine.go         # Coraza WAF core wrapper, stats, hot-reload mechanism
│       ├── proxy.go          # Custom ReverseProxy handler, domain router, error interceptor
│       ├── block.go          # HTML template renderer for custom 403 block pages
│       ├── botdetect.go      # Search engine crawler whitelisting & malicious bot heuristics
│       ├── ipreputation.go   # CIDR-based IP Whitelist / Blacklist middleware
│       ├── ratelimit.go      # Sliding window per-IP rate limiter & auto-banning
│       ├── requestvalidator.go # Structural request validation (max body, URI length, headers)
│       ├── securityheaders.go # Security response headers (HSTS, CSP, Frame-Options, CORS)
│       └── threatlogger.go   # Structured JSON logging for security events
├── scripts/
│   ├── install.sh            # One-click Linux VPS installer script
│   └── lim-waf.service       # Systemd service unit definition
├── testenv/                  # Local test environment setup
├── Dockerfile                # Multi-stage Alpine build file
└── Makefile                  # Build targets (make build, make release)
```

---

## 3. Middleware Execution Chain (Order Matters!)

Traffic flowing into `ReverseProxy` follows this exact wrapper sequence:

```
[Client Request]
       │
       ▼
1. ThreatLogger        ──► Captures timing, request details & status codes
       │
       ▼
2. RateLimiter         ──► Enforces per-IP & per-path request limits / bans
       │
       ▼
3. IPReputation        ──► Passes whitelisted IPs / blocks blacklisted CIDRs
       │
       ▼
4. BotDetection        ──► Bypasses legitimate search crawlers (Google, Bing) / blocks honeypot & fake UA
       │
       ▼
5. RequestValidator    ──► Validates URL length, header sizes, blocked file extensions, body limits
       │
       ▼
6. SecurityHeaders     ──► Injects HSTS, CSP, X-Frame-Options, CORS headers
       │
       ▼
7. Coraza WAF Engine   ──► Executes OWASP CRS v4 & custom ModSecurity rules
       │
       ▼
8. ReverseProxy        ──► Proxies allowed traffic to target backend URL
```

---

## 4. Current Supported Features & Truth Baseline

Agents **MUST NOT** hallucinate or claim support for features that are not explicitly implemented. Below is the ground-truth status:

| Feature | Implementation Status | Location | Notes |
|---|---|---|---|
| OWASP CRS v4 | ✅ Full | `engine.go` | Loaded from `crs_path` |
| Custom ModSecurity Rules | ✅ Full | `engine.go` | Loaded from `custom_rules_path` |
| Custom 403 Block Page | ✅ Full | `block.go`, `templates/block.html` | "Secured by LIM" branding |
| Domain Host Validation | ✅ Full | `proxy.go` | Blocks unmatched host headers |
| Search Engine Bot Whitelist | ✅ Full | `botdetect.go` | Googlebot, Bingbot, Yahoo, DuckDuckGo, Baidu, Yandex |
| Reverse DNS Bot Verification| ✅ Supported (`verify_bots_by_dns`) | `botdetect.go` | Verifies FCrDNS to prevent Googlebot UA spoofing |
| Per-Path Rate Limiting | ✅ Full | `ratelimit.go` | Configurable pattern matching |
| IP Whitelist / Blacklist | ✅ Full | `ipreputation.go` | Supports IPv4/IPv6 single IPs & CIDR blocks |
| Admin Dashboard | ✅ Full | `dashboard.go` | Features rule hot-reload, stats, threat logs, live config edit |
| Coraza Audit Logging | ✅ Full | `engine.go` | Uses `SecAuditEngine RelevantOnly` |
| Tor Exit Node Blocking | ❌ Not Implemented | — | Field removed from config |
| Automatic IP Reputation API | ❌ Not Implemented | — | Field removed from config |

---

## 5. Development Guidelines & Rules for Agents

1. **No Phantom Imports or Dependencies**: Use Go standard library where possible (`net`, `net/http`, `strings`, `sync`, `time`). External deps are strictly Coraza `v3.7.0`, Cobra, YAML v3, and x/crypto.
2. **Atomic Stats Updates**: Always use `sync/atomic` for updating counters in `WAFStats`.
3. **Hot Reload Compatibility**: Any new module or config change must support clean reloading via `WAFEngine.Reload(cfg)`.
4. **No Code Duplication**: Do not inline checks that belong in specific middleware files.
5. **Clean Code & Zero Dead Functions**: Unused functions, unreferenced config fields, or dead logic must be pruned immediately.
