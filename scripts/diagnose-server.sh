#!/usr/bin/env bash
# SSH CA Server Diagnostic Script
# Run this on the SSH server (quebec)

set -euo pipefail

echo "=== SSH CA Server Diagnostics ==="
echo

echo "1. Checking sshd configuration..."
echo "-----------------------------------"
if grep -E "^TrustedUserCAKeys" /etc/ssh/sshd_config; then
    echo "✓ TrustedUserCAKeys is configured"
else
    echo "✗ TrustedUserCAKeys NOT found in sshd_config"
    echo "  Checking sshd_config.d/..."
    grep -r "TrustedUserCAKeys" /etc/ssh/sshd_config.d/ 2>/dev/null || echo "  Not found in sshd_config.d either"
fi
echo

echo "2. Verifying CA public key file..."
echo "-----------------------------------"
if [ -f /etc/ssh/ssh_user_ca.pub ]; then
    echo "✓ CA public key exists: /etc/ssh/ssh_user_ca.pub"
    echo "  Content:"
    cat /etc/ssh/ssh_user_ca.pub
    echo "  Permissions: $(stat -c '%a' /etc/ssh/ssh_user_ca.pub)"
else
    echo "✗ CA public key NOT found at /etc/ssh/ssh_user_ca.pub"
fi
echo

echo "3. Testing sshd configuration..."
echo "-----------------------------------"
if sshd -t 2>&1; then
    echo "✓ sshd configuration is valid"
else
    echo "✗ sshd configuration has errors"
fi
echo

echo "4. Checking sshd service status..."
echo "-----------------------------------"
systemctl status sshd 2>/dev/null || systemctl status ssh 2>/dev/null || echo "Unable to check sshd status"
echo

echo "5. Checking authentication logs (last 20 lines)..."
echo "-----------------------------------"
echo "Recent auth attempts:"
tail -20 /var/log/auth.log 2>/dev/null || tail -20 /var/log/secure 2>/dev/null || echo "Unable to read auth logs"
echo

echo "6. Checking if user 'adams' exists..."
echo "-----------------------------------"
if id adams &>/dev/null; then
    echo "✓ User 'adams' exists"
    echo "  Home: $(eval echo ~adams)"
    echo "  Shell: $(getent passwd adams | cut -d: -f7)"
else
    echo "✗ User 'adams' does NOT exist"
fi
echo

echo "=== Diagnostic Complete ==="
echo
echo "Next steps:"
echo "1. If TrustedUserCAKeys is missing, add to /etc/ssh/sshd_config:"
echo "   TrustedUserCAKeys /etc/ssh/ssh_user_ca.pub"
echo "2. If user doesn't exist, create it: useradd -m adams"
echo "3. After changes, reload sshd: systemctl reload sshd"
