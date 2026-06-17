# LIM WAF

**LIM WAF** is a custom, branded Web Application Firewall (WAF) powered by the high-performance [Coraza Engine](https://coraza.io) and fully compatible with OWASP Core Rule Set (CRS) v4.

Instead of installing a raw WAF engine, LIM WAF is packaged as a ready-to-deploy reverse proxy specifically designed for VPS installations. It features custom-branded error pages indicating "**Secured by LIM**" and includes an embedded admin dashboard.

## Features
- **Powered by Coraza**: Robust security powered by Go and OWASP ModSecurity compatibility.
- **OWASP CRS v4 Ready**: Protects against SQLi, XSS, RCE, and more out-of-the-box.
- **Custom Branding**: Fully branded "403 Access Denied" block pages linked to `https://nuralim.dev`.
- **Admin Dashboard**: Real-time stats and rule hot-reloading via an embedded web interface (port 9443).
- **Single-Binary Reverse Proxy**: Easily placed in front of your applications. TLS is intended to be handled by upstream load balancers (e.g., Cloudflare or a front-facing proxy).

## Architecture

1. **Client** sends request -> **Upstream Proxy (Optional)** -> **LIM WAF (:80)**.
2. **LIM WAF** inspects the request using Coraza rules.
3. If **malicious**, it displays a custom block page.
4. If **safe**, it proxies the request to your backend.

## Installation

A convenient install script is provided for Ubuntu/Debian based systems.

1. Clone or download this repository.
2. Build the binary using `make build`.
3. Run the installer:
   ```bash
   sudo ./scripts/install.sh
   ```

The script will:
- Copy the binary to `/usr/local/bin`
- Download the latest OWASP Core Rule Set (CRS)
- Create default configurations in `/etc/lim-waf`
- Set up a systemd service (`lim-waf.service`)

## Configuration

Configuration is located at `/etc/lim-waf/config.yaml`.

```yaml
server:
  listen: ":80"

sites:
  - domain: "example.com"
    backend: "http://127.0.0.1:8080" # Your actual application backend
    waf:
      enabled: true
      mode: "on" # "on", "detection_only", or "off"

rules:
  crs_path: "/etc/lim-waf/rules/coreruleset"
  custom_rules_path: "/etc/lim-waf/rules/custom"

branding:
  name: "LIM"
  url: "https://nuralim.dev"
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
