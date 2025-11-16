package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// BootstrapHandler handles bootstrap script requests
type BootstrapHandler struct {
	serverScriptContent string
	clientScriptContent string
}

// NewBootstrapHandler creates a new bootstrap handler
func NewBootstrapHandler() *BootstrapHandler {
	return &BootstrapHandler{
		serverScriptContent: getServerBootstrapScript(),
		clientScriptContent: getClientBootstrapScript(),
	}
}

// GetServerScript returns the server bootstrap script
// GET /v1/bootstrap/server.sh
func (h *BootstrapHandler) GetServerScript(c *gin.Context) {
	c.Data(http.StatusOK, "text/x-shellscript; charset=utf-8", []byte(h.serverScriptContent))
}

// GetClientScript returns the client bootstrap script
// GET /v1/bootstrap/client.sh
func (h *BootstrapHandler) GetClientScript(c *gin.Context) {
	c.Data(http.StatusOK, "text/x-shellscript; charset=utf-8", []byte(h.clientScriptContent))
}

// getServerBootstrapScript returns the server bootstrap script content
func getServerBootstrapScript() string {
	return `#!/usr/bin/env bash
#
# Server Bootstrap Script for SSH CA
# This script configures a server to trust the SSH CA
#

set -euo pipefail

CA_SERVER="${CA_SERVER:-https://ca.smartcubes.uk}"
CA_KEY_URL="$CA_SERVER/v1/ca/user"
REGISTER_URL="$CA_SERVER/v1/register/server"

echo "=== SSH CA Server Bootstrap ==="
echo "CA Server: $CA_SERVER"

# Check root
if [ "$EUID" -ne 0 ]; then
    echo "Error: This script must be run as root"
    exit 1
fi

# Download CA public key
echo "Downloading CA public key..."
mkdir -p /etc/ssh
curl -fsSL "$CA_KEY_URL" -o /etc/ssh/ssh_user_ca.pub
chmod 644 /etc/ssh/ssh_user_ca.pub

# Configure sshd
echo "Configuring sshd..."
if ! grep -q "TrustedUserCAKeys" /etc/ssh/sshd_config; then
    echo "TrustedUserCAKeys /etc/ssh/ssh_user_ca.pub" >> /etc/ssh/sshd_config
fi

# Reload sshd
echo "Reloading sshd..."
systemctl reload sshd || systemctl restart sshd

# Collect system info
HOSTNAME=$(hostname)
OS=$(grep ^PRETTY_NAME /etc/os-release | cut -d= -f2- | tr -d '"')
KERNEL=$(uname -r)
ARCH=$(uname -m)
IP_ADDRESSES=$(ip -4 addr | grep inet | grep -v 127.0.0.1 | awk '{print $2}' | cut -d/ -f1 | tr '\n' ',' | sed 's/,$//')
SSH_VERSION=$(sshd -V 2>&1 | head -n1)

# Register server
echo "Registering server..."
curl -fsSL -X POST "$REGISTER_URL" \
    -H "Content-Type: application/json" \
    -d "{
        \"hostname\": \"$HOSTNAME\",
        \"os\": \"$OS\",
        \"kernel\": \"$KERNEL\",
        \"arch\": \"$ARCH\",
        \"ip_addresses\": [\"${IP_ADDRESSES//,/\",\"}\"],
        \"ssh_version\": \"$SSH_VERSION\",
        \"ca_trusted\": true
    }"

echo ""
echo "=== Bootstrap Complete ==="
echo "Server is now configured to trust SSH CA certificates"
`
}

// getClientBootstrapScript returns the client bootstrap script content
func getClientBootstrapScript() string {
	return `#!/usr/bin/env bash
#
# Client Bootstrap Script for SSH CA
# This script sets up SSH certificate authentication
#

set -euo pipefail

CA_SERVER="${CA_SERVER:-https://ca.smartcubes.uk}"
CA_KEY_URL="$CA_SERVER/v1/ca/user"
ISSUE_URL="$CA_SERVER/v1/certs/issue"

echo "=== SSH CA Client Bootstrap ==="
echo "CA Server: $CA_SERVER"

# Check dependencies
for cmd in ssh ssh-keygen curl; do
    if ! command -v $cmd &> /dev/null; then
        echo "Error: $cmd is required but not installed"
        exit 1
    fi
done

# Check for JSON parser
if command -v jq &> /dev/null; then
    JSON_PARSER="jq"
elif command -v python3 &> /dev/null; then
    JSON_PARSER="python3"
else
    echo "Error: Either 'jq' or 'python3' is required for JSON parsing"
    exit 1
fi

# Get user info
read -p "Username: " USERNAME
read -sp "Password: " PASSWORD
echo ""
read -p "TOTP Code: " TOTP

# Generate SSH key if not exists
KEY_FILE="$HOME/.ssh/id_ed25519_ca"
if [ ! -f "$KEY_FILE" ]; then
    echo "Generating SSH key..."
    ssh-keygen -t ed25519 -f "$KEY_FILE" -N "" -C "$USERNAME@$(hostname)"
fi

# Read public key
PUBKEY=$(cat "$KEY_FILE.pub")
HOSTNAME=$(hostname)

# Request certificate
echo "Requesting certificate..."
RESPONSE=$(curl -fsSL -X POST "$ISSUE_URL" \
    -H "Content-Type: application/json" \
    -d "{
        \"username\": \"$USERNAME\",
        \"password\": \"$PASSWORD\",
        \"totp\": \"$TOTP\",
        \"public_key\": \"$PUBKEY\",
        \"client_hostname\": \"$HOSTNAME\",
        \"requested_principals\": [\"$USERNAME\"],
        \"requested_validity\": \"24h\"
    }")

# Extract certificate and token using appropriate JSON parser
if [ "$JSON_PARSER" = "jq" ]; then
    CERT=$(echo "$RESPONSE" | jq -r '.certificate')
    RENEW_TOKEN=$(echo "$RESPONSE" | jq -r '.renew_token')
else
    # Use Python for JSON parsing
    CERT=$(echo "$RESPONSE" | python3 -c "import sys, json; print(json.load(sys.stdin)['certificate'], end='')")
    RENEW_TOKEN=$(echo "$RESPONSE" | python3 -c "import sys, json; print(json.load(sys.stdin).get('renew_token', ''), end='')")
fi

# Validate certificate
if [ -z "$CERT" ] || [ "$CERT" = "null" ]; then
    echo "Error: Failed to get certificate from server"
    echo "Response: $RESPONSE"
    exit 1
fi

# Save certificate (use printf to avoid adding newline)
printf "%s" "$CERT" > "$KEY_FILE-cert.pub"
echo "Certificate saved to $KEY_FILE-cert.pub"

# Save renew token
if [ -n "$RENEW_TOKEN" ]; then
    echo "$RENEW_TOKEN" > "$HOME/.ssh/ssh_ca_renew_token"
    chmod 600 "$HOME/.ssh/ssh_ca_renew_token"
    echo "Renew token saved"
fi

# Configure SSH to use CA key by default
SSH_CONFIG="$HOME/.ssh/config"
echo ""
echo "Configuring SSH client..."

# Create .ssh/config if it doesn't exist
if [ ! -f "$SSH_CONFIG" ]; then
    touch "$SSH_CONFIG"
    chmod 600 "$SSH_CONFIG"
fi

# Check if CA key configuration already exists
if ! grep -q "IdentityFile.*id_ed25519_ca" "$SSH_CONFIG"; then
    # Backup existing config
    cp "$SSH_CONFIG" "$SSH_CONFIG.bak.$(date +%s)" 2>/dev/null || true

    # Add CA key configuration at the beginning
    {
        echo "# SSH CA Certificate Authentication"
        echo "# Added by CA bootstrap script on $(date)"
        echo "Host *"
        echo "    IdentityFile ~/.ssh/id_ed25519_ca"
        echo "    IdentitiesOnly no"
        echo ""
        cat "$SSH_CONFIG"
    } > "$SSH_CONFIG.tmp"

    mv "$SSH_CONFIG.tmp" "$SSH_CONFIG"
    chmod 600 "$SSH_CONFIG"
    echo "✓ SSH config updated to prioritize CA certificate key"
else
    echo "✓ SSH config already configured for CA certificate"
fi

echo ""

# Create automatic renewal script
RENEW_SCRIPT="$HOME/.ssh/ssh_ca_renew.sh"
echo "Creating automatic certificate renewal script..."

cat > "$RENEW_SCRIPT" << 'RENEW_SCRIPT_EOF'
#!/usr/bin/env bash
# Automatic SSH Certificate Renewal Script
# Generated by SSH CA bootstrap script

set -euo pipefail

# Configuration
API_URL="${CA_SERVER:-https://ca.smartcubes.uk}"
KEY_FILE="$HOME/.ssh/id_ed25519_ca"
CERT_FILE="$HOME/.ssh/id_ed25519_ca-cert.pub"
TOKEN_FILE="$HOME/.ssh/ssh_ca_renew_token"
RENEW_URL="$API_URL/v1/certs/renew"
LOG_FILE="$HOME/.ssh/ssh_ca_renew.log"

# Threshold: renew when less than 12 hours remaining
THRESHOLD=43200

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG_FILE"
}

# Check if certificate file exists
if [ ! -f "$CERT_FILE" ]; then
    log "Certificate file not found, skipping renewal"
    exit 0
fi

# Check certificate validity
if ! ssh-keygen -L -f "$CERT_FILE" >/dev/null 2>&1; then
    log "Certificate file is invalid"
    exit 1
fi

# Extract expiry time
VALID_TO=$(ssh-keygen -L -f "$CERT_FILE" 2>/dev/null | grep "Valid:" | sed -E 's/.*to ([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}).*/\1/')

if [ -z "$VALID_TO" ]; then
    log "Could not parse certificate expiry time"
    exit 1
fi

# Convert to timestamp (Linux date command)
EXPIRY_TS=$(date -d "$VALID_TO" +%s 2>/dev/null || echo 0)
NOW_TS=$(date +%s)
REMAINING=$((EXPIRY_TS - NOW_TS))

if [ $REMAINING -gt $THRESHOLD ]; then
    log "Certificate still valid ($(($REMAINING / 3600)) hours remaining), no renewal needed"
    exit 0
fi

log "Certificate expiring soon ($(($REMAINING / 3600)) hours remaining), attempting renewal..."

# Check for renew token
if [ ! -f "$TOKEN_FILE" ]; then
    log "ERROR: Renew token not found at $TOKEN_FILE"
    exit 1
fi

# Read token and public key
TOKEN=$(cat "$TOKEN_FILE")
PUBKEY=$(cat "$KEY_FILE.pub")

# Determine JSON method
if command -v jq &> /dev/null; then
    JSON_DATA=$(jq -n \
        --arg pubkey "$PUBKEY" \
        --arg token "$TOKEN" \
        '{public_key: $pubkey, renew_token: $token, requested_validity: "24h"}')
elif command -v python3 &> /dev/null; then
    JSON_DATA=$(python3 -c "import json; print(json.dumps({'public_key': '''$PUBKEY''', 'renew_token': '''$TOKEN''', 'requested_validity': '24h'}))")
else
    log "ERROR: Neither jq nor python3 available for JSON generation"
    exit 1
fi

# Attempt renewal
RESPONSE=$(curl -fsSL -X POST "$RENEW_URL" \
    -H "Content-Type: application/json" \
    -d "$JSON_DATA" 2>&1) || {
    log "ERROR: Renewal request failed: $RESPONSE"
    exit 1
}

# Extract new certificate
if command -v jq &> /dev/null; then
    NEW_CERT=$(echo "$RESPONSE" | jq -r '.certificate' 2>/dev/null)
elif command -v python3 &> /dev/null; then
    NEW_CERT=$(echo "$RESPONSE" | python3 -c "import sys, json; print(json.load(sys.stdin).get('certificate', ''), end='')" 2>/dev/null)
else
    log "ERROR: Cannot parse JSON response"
    exit 1
fi

# Validate new certificate
if [ -z "$NEW_CERT" ] || [ "$NEW_CERT" = "null" ]; then
    log "ERROR: Failed to extract certificate from response: $RESPONSE"
    exit 1
fi

# Save new certificate
printf "%s" "$NEW_CERT" > "$CERT_FILE.new"

# Verify new certificate is valid
if ssh-keygen -L -f "$CERT_FILE.new" >/dev/null 2>&1; then
    mv "$CERT_FILE.new" "$CERT_FILE"
    log "SUCCESS: Certificate renewed successfully"

    # Extract new expiry
    NEW_VALID_TO=$(ssh-keygen -L -f "$CERT_FILE" 2>/dev/null | grep "Valid:" | sed -E 's/.*to ([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}).*/\1/')
    log "New certificate valid until: $NEW_VALID_TO"
else
    log "ERROR: New certificate is invalid"
    rm -f "$CERT_FILE.new"
    exit 1
fi
RENEW_SCRIPT_EOF

chmod 700 "$RENEW_SCRIPT"
echo "✓ Renewal script created: $RENEW_SCRIPT"

# Install crontab entry
echo ""
echo "Installing automatic renewal to crontab..."

# Check if crontab entry already exists
if crontab -l 2>/dev/null | grep -q "ssh_ca_renew.sh"; then
    echo "✓ Crontab entry already exists"
else
    # Get current crontab
    CURRENT_CRONTAB=$(crontab -l 2>/dev/null || echo "")

    # Add new entry
    (
        echo "$CURRENT_CRONTAB"
        echo ""
        echo "# SSH CA Certificate Auto-Renewal (checks every 30 minutes)"
        echo "*/30 * * * * $HOME/.ssh/ssh_ca_renew.sh >/dev/null 2>&1"
    ) | crontab -

    echo "✓ Crontab entry added (runs every 30 minutes)"
    echo "  To view: crontab -l"
    echo "  To remove: crontab -e"
fi

# Test renewal script syntax
echo ""
echo "Testing renewal script..."
if bash -n "$RENEW_SCRIPT"; then
    echo "✓ Renewal script syntax is valid"
else
    echo "✗ Warning: Renewal script has syntax errors"
fi

echo ""
echo "=== Bootstrap Complete ==="
echo ""
echo "Summary:"
echo "  SSH key: $KEY_FILE"
echo "  Certificate: $KEY_FILE-cert.pub"
echo "  Renew token: $HOME/.ssh/ssh_ca_renew_token"
echo "  Renewal script: $RENEW_SCRIPT"
echo "  Renewal log: $HOME/.ssh/ssh_ca_renew.log"
echo ""
echo "Your SSH client is configured to:"
echo "  ✓ Use CA certificates by default (see ~/.ssh/config)"
echo "  ✓ Automatically renew certificates every 30 minutes"
echo ""
echo "Test SSH connection:"
echo "  ssh $USERNAME@<server>"
echo ""
echo "Manual renewal (if needed):"
echo "  bash $RENEW_SCRIPT"
`
}
