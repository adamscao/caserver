#!/usr/bin/env bash
# SSH CA Client Diagnostic Script
# Run this on the client machine (nixos)

set -euo pipefail

echo "=== SSH CA Client Diagnostics ==="
echo

echo "1. Checking SSH key files..."
echo "-----------------------------------"
if [ -f ~/.ssh/id_ed25519_ca ]; then
    echo "✓ Private key exists: ~/.ssh/id_ed25519_ca"
    echo "  Permissions: $(stat -c '%a' ~/.ssh/id_ed25519_ca 2>/dev/null || stat -f '%Lp' ~/.ssh/id_ed25519_ca)"
else
    echo "✗ Private key NOT found"
fi

if [ -f ~/.ssh/id_ed25519_ca.pub ]; then
    echo "✓ Public key exists: ~/.ssh/id_ed25519_ca.pub"
    echo "  Content:"
    cat ~/.ssh/id_ed25519_ca.pub
else
    echo "✗ Public key NOT found"
fi

if [ -f ~/.ssh/id_ed25519_ca-cert.pub ]; then
    echo "✓ Certificate exists: ~/.ssh/id_ed25519_ca-cert.pub"
else
    echo "✗ Certificate NOT found"
fi
echo

echo "2. Checking certificate validity..."
echo "-----------------------------------"
if [ -f ~/.ssh/id_ed25519_ca-cert.pub ]; then
    echo "Certificate details:"
    ssh-keygen -L -f ~/.ssh/id_ed25519_ca-cert.pub
    echo

    # Extract validity period
    VALID_FROM=$(ssh-keygen -L -f ~/.ssh/id_ed25519_ca-cert.pub | grep "Valid:" | sed 's/.*from //' | sed 's/ to.*//')
    VALID_TO=$(ssh-keygen -L -f ~/.ssh/id_ed25519_ca-cert.pub | grep "Valid:" | sed 's/.*to //')

    echo "Valid from: $VALID_FROM"
    echo "Valid to: $VALID_TO"
    echo "Current time: $(date)"

    # Check if cert is expired
    if ssh-keygen -L -f ~/.ssh/id_ed25519_ca-cert.pub | grep -q "Valid:"; then
        echo "✓ Certificate has validity period"
    fi
else
    echo "No certificate to check"
fi
echo

echo "3. Checking renew token..."
echo "-----------------------------------"
if [ -f ~/.ssh/ssh_ca_renew_token ]; then
    echo "✓ Renew token exists"
    echo "  Permissions: $(stat -c '%a' ~/.ssh/ssh_ca_renew_token 2>/dev/null || stat -f '%Lp' ~/.ssh/ssh_ca_renew_token)"
else
    echo "✗ Renew token NOT found"
fi
echo

echo "4. Testing SSH connection (verbose)..."
echo "-----------------------------------"
echo "Please enter the server hostname/IP to test:"
read -p "Server: " SERVER

if [ -n "$SERVER" ]; then
    echo "Attempting connection with verbose output..."
    ssh -v -i ~/.ssh/id_ed25519_ca -o IdentitiesOnly=yes adams@$SERVER "echo 'Connection successful!'" 2>&1 | tail -30
else
    echo "Skipping connection test"
fi
echo

echo "=== Diagnostic Complete ==="
