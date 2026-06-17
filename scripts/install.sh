#!/bin/bash
set -e

echo "============================================="
echo "   Installing LIM WAF (Coraza Powered)       "
echo "============================================="

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (sudo)"
  exit 1
fi

LIM_WAF_VERSION="latest" # Or specific version from GitHub Releases
BIN_DIR="/usr/local/bin"
CONF_DIR="/etc/lim-waf"
LOG_DIR="/var/log/lim-waf"
RULES_DIR="$CONF_DIR/rules"

echo "[1/5] Creating directories..."
mkdir -p "$CONF_DIR"
mkdir -p "$RULES_DIR/custom"
mkdir -p "$LOG_DIR"
chown -R root:root "$CONF_DIR"
chown -R root:adm "$LOG_DIR"
chmod 750 "$LOG_DIR"

echo "[2/5] Downloading LIM WAF binary..."
# Note: For production, point this to the actual GitHub Release URL
# Example: curl -sL "https://github.com/nrlim/lim-waf/releases/latest/download/lim-waf-linux-amd64" -o "$BIN_DIR/lim-waf"
# For now, we assume the binary is built locally or will be available.
if [ -f "./build/lim-waf" ]; then
    cp ./build/lim-waf "$BIN_DIR/lim-waf"
    chmod +x "$BIN_DIR/lim-waf"
    echo "  Local binary installed."
else
    echo "  WARN: Binary not found in ./build. Please build it first or download manually."
fi

echo "[3/5] Setting up OWASP Core Rule Set (CRS) v4..."
if [ ! -d "$RULES_DIR/coreruleset" ]; then
    apt-get update -qq && apt-get install -qq -y git
    git clone -b v4.0/master https://github.com/coreruleset/coreruleset.git "$RULES_DIR/coreruleset"
    cp "$RULES_DIR/coreruleset/crs-setup.conf.example" "$RULES_DIR/coreruleset/crs-setup.conf"
    echo "  OWASP CRS v4 downloaded."
else
    echo "  OWASP CRS already exists."
fi

echo "[4/5] Creating default configuration..."
if [ ! -f "$CONF_DIR/config.yaml" ]; then
cat <<EOF > "$CONF_DIR/config.yaml"
server:
  listen: ":80"
  tls:
    enabled: false
    cert: ""
    key: ""

sites:
  - domain: "example.com"
    backend: "http://127.0.0.1:8080"
    waf:
      enabled: true
      mode: "on"

rules:
  crs_path: "$RULES_DIR/coreruleset"
  custom_rules_path: "$RULES_DIR/custom"

logging:
  level: "info"
  file: "$LOG_DIR/access.log"
  audit_log: "$LOG_DIR/audit.log"

branding:
  name: "LIM"
  url: "https://nuralim.dev"
EOF
    echo "  Default config.yaml created."
else
    echo "  Config already exists, skipping."
fi

echo "[5/5] Setting up systemd service..."
if [ -f "./scripts/lim-waf.service" ]; then
    cp ./scripts/lim-waf.service /etc/systemd/system/
    systemctl daemon-reload
    systemctl enable lim-waf
    echo "  Systemd service configured (use 'systemctl start lim-waf' to start)."
else
    echo "  WARN: lim-waf.service file not found in ./scripts/"
fi

echo "============================================="
echo " LIM WAF Installation Complete!              "
echo " Configuration: $CONF_DIR/config.yaml        "
echo " Logs: $LOG_DIR                              "
echo "                                             "
echo " To start: systemctl start lim-waf           "
echo "============================================="
