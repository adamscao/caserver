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
echo "=== Bootstrap Complete ==="
echo "Your SSH client is now configured to use CA certificates by default"
echo "Test with: ssh $USERNAME@<server>"
`
}
