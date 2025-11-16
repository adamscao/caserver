#!/usr/bin/env bash
#
# Fix SSH server configuration for CA authentication
# Run on the SSH server as root
#

set -euo pipefail

echo "=== SSH CA Server Configuration Fix ==="
echo

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Error: This script must be run as root"
    echo "Usage: sudo $0"
    exit 1
fi

# 1. Ensure CA public key exists
if [ ! -f /etc/ssh/ssh_user_ca.pub ]; then
    echo "Error: CA public key not found at /etc/ssh/ssh_user_ca.pub"
    echo "Please run the server bootstrap script first:"
    echo "  curl https://ca.smartcubes.uk/v1/bootstrap/server.sh | sudo bash"
    exit 1
fi

echo "✓ CA public key exists"
echo "  Content: $(cat /etc/ssh/ssh_user_ca.pub)"
echo

# 2. Configure TrustedUserCAKeys properly
echo "Configuring TrustedUserCAKeys..."

# Remove any existing TrustedUserCAKeys lines (including commented ones)
sed -i.bak '/TrustedUserCAKeys/d' /etc/ssh/sshd_config

# Add TrustedUserCAKeys at the end of the file
echo "" >> /etc/ssh/sshd_config
echo "# SSH CA Configuration" >> /etc/ssh/sshd_config
echo "TrustedUserCAKeys /etc/ssh/ssh_user_ca.pub" >> /etc/ssh/sshd_config

echo "✓ Added TrustedUserCAKeys to /etc/ssh/sshd_config"
echo

# 3. Optionally enable other useful settings
echo "Enabling recommended sshd settings..."

# Enable public key authentication if not already enabled
if ! grep -q "^PubkeyAuthentication yes" /etc/ssh/sshd_config; then
    sed -i.bak2 's/^#*PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config
    echo "✓ Enabled PubkeyAuthentication"
fi

# Enable AuthorizedPrincipalsFile if you want to use it
# Uncomment if needed:
# echo "AuthorizedPrincipalsFile /etc/ssh/principals/%u" >> /etc/ssh/sshd_config

echo

# 4. Test configuration
echo "Testing sshd configuration..."
if sshd -t; then
    echo "✓ sshd configuration is valid"
else
    echo "✗ sshd configuration has errors!"
    echo "  Restoring backup..."
    mv /etc/ssh/sshd_config.bak /etc/ssh/sshd_config
    exit 1
fi
echo

# 5. Reload sshd
echo "Reloading sshd service..."
if systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null; then
    echo "✓ sshd reloaded successfully"
else
    echo "Trying restart instead..."
    systemctl restart sshd 2>/dev/null || systemctl restart ssh
    echo "✓ sshd restarted"
fi
echo

# 6. Show current configuration
echo "Current SSH CA configuration:"
echo "-----------------------------------"
grep -A 2 "SSH CA Configuration" /etc/ssh/sshd_config
echo

echo "=== Configuration Complete ==="
echo
echo "You can now test SSH certificate authentication:"
echo "  ssh -i ~/.ssh/id_ed25519_ca adams@$(hostname)"
echo
echo "To view authentication logs in real-time:"
echo "  tail -f /var/log/auth.log  # (or /var/log/secure)"
