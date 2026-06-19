# LIM WAF

**LIM WAF** is a custom, branded Web Application Firewall (WAF) powered by a high-performance Go-based engine and fully compatible with OWASP Core Rule Set (CRS) v4.

Instead of installing a raw WAF engine, LIM WAF is packaged as a ready-to-deploy reverse proxy specifically designed for VPS installations. It features custom-branded error pages indicating "**Secured by LIM**" and includes an embedded admin dashboard.

## Features
- **High-Performance Engine**: Robust security powered by Go and OWASP ModSecurity compatibility.
- **OWASP CRS v4 Ready**: Protects against SQLi, XSS, RCE, and more out-of-the-box.
- **Custom Branding**: Fully branded "403 Access Denied" block pages linked to `https://nuralim.dev`.
- **Admin Dashboard**: Real-time stats and rule hot-reloading via an embedded web interface (port 9443).
- **Single-Binary Reverse Proxy**: Easily placed in front of your applications. TLS is intended to be handled by upstream load balancers (e.g., Cloudflare or a front-facing proxy).

## Architecture

1. **Client** sends request -> **Upstream Proxy (Optional)** -> **LIM WAF (:80)**.
2. **LIM WAF** inspects the request using the Core Rule Set.
3. If **malicious**, it displays a custom block page.
4. If **safe**, it proxies the request to your backend.

## Installation & VPS Deployment

Since LIM WAF compiles to a single static binary, you don't need to install Go or any development tools on your production VPS. The cleanest way to install is to place the installer files in `/opt`.

### 1. Build Locally (Linux Target)
On your local machine (Windows/Mac/Linux), compile the binary specifically for Linux architecture:

```powershell
# If using Windows PowerShell:
$env:GOOS="linux"; $env:GOARCH="amd64"; go build -o lim-waf-linux ./cmd/lim-waf

# If using Mac/Linux Bash:
GOOS=linux GOARCH=amd64 go build -o lim-waf-linux ./cmd/lim-waf
```

### 2. Upload to VPS (`/opt` Directory)
Create a clean directory in your VPS for the installer, then upload the files:

```bash
# On your VPS, prepare the installer folder:
sudo mkdir -p /opt/lim-waf-installer/build
sudo chown -R $USER:$USER /opt/lim-waf-installer

# On your local machine, upload the files directly to that folder:
scp lim-waf-linux root@YOUR_VPS_IP:/opt/lim-waf-installer/build/lim-waf
scp -r scripts root@YOUR_VPS_IP:/opt/lim-waf-installer/
```

### 3. Run the Installer
SSH into your VPS and execute the setup script:

```bash
cd /opt/lim-waf-installer
sudo chmod +x scripts/install.sh
sudo ./scripts/install.sh
```

The script will securely distribute the files:
- Binary installed to: `/usr/local/bin/lim-waf`
- OWASP CRS v4 rules and configs to: `/etc/lim-waf/`
- Service configured at: `/etc/systemd/system/lim-waf.service`

## Best Practice Configuration (Multi-Domain with Nginx)

The recommended topology is placing LIM WAF between your Nginx SSL termination and your backend applications:
`Internet ➜ Nginx (Port 443) ➜ LIM WAF (Port 8081) ➜ Backend Apps`

Edit your `/etc/lim-waf/config.yaml` to handle multiple domains:

```yaml
server:
  listen: ":8081" # Internal WAF Port

sites:
  # App 1
  - domain: "example1.com"
    backend: "http://127.0.0.1:3000"
    waf:
      enabled: true
      mode: "on"

  # App 2
  - domain: "example2.com"
    backend: "http://127.0.0.1:3001"
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
```

After configuring, restart the service:
```bash
sudo systemctl restart lim-waf
```

**Nginx Setup:** In your Nginx config (`/etc/nginx/sites-enabled/...`), change your backend `proxy_pass` to point to LIM WAF:
```nginx
proxy_pass http://127.0.0.1:8081; # Pass traffic to WAF
```

## Running

If installed via script, start it using systemd:

```bash
sudo systemctl start lim-waf
sudo systemctl enable lim-waf
sudo systemctl status lim-waf
```

For manual testing:
```bash
lim-waf serve --config /etc/lim-waf/config.yaml
```

## Admin Dashboard

The admin dashboard is available on localhost at `http://127.0.0.1:9443/`. It provides insights into total requests, blocked requests, and allows you to reload WAF rules dynamically. To access it externally securely, use SSH port forwarding:
```bash
ssh -L 9443:127.0.0.1:9443 root@your-vps-ip
```

## Development

Build the project locally using `make`:

```bash
make build
```

The resulting binary will be placed in the `build/` directory.

---
*Secured by [LIM](https://nuralim.dev)*
