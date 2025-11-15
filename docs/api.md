# SSH CA Server API Documentation

**Version:** 1.0
**Base URL:** `https://ca.example.com`
**Protocol:** HTTPS only

---

## Table of Contents

1. [Authentication](#authentication)
2. [Error Responses](#error-responses)
3. [Public Endpoints](#public-endpoints)
4. [User Endpoints](#user-endpoints)
5. [Admin Endpoints](#admin-endpoints)
6. [Rate Limiting](#rate-limiting)
7. [Examples](#examples)

---

## Authentication

### Admin Endpoints

Admin endpoints require authentication via the `X-Admin-Token` header.

**Header:**
```
X-Admin-Token: your-secure-admin-token
```

**Example:**
```bash
curl -X POST https://ca.example.com/v1/admin/users \
  -H "X-Admin-Token: your-secure-admin-token" \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"secret","totp_secret":"ABC123","enabled":true}'
```

### User Endpoints

User endpoints require authentication via request body parameters (username, password, TOTP for issue; renew_token for renew).

---

## Error Responses

All error responses follow this format:

```json
{
  "error": "error_code",
  "message": "Human-readable error message",
  "details": {}
}
```

### Common Error Codes

| HTTP Status | Error Code | Description |
|-------------|------------|-------------|
| 400 | `invalid_request` | Malformed request body or parameters |
| 400 | `invalid_public_key` | Invalid SSH public key format |
| 400 | `invalid_validity` | Invalid validity period format |
| 401 | `invalid_credentials` | Wrong username or password |
| 401 | `invalid_totp` | Wrong TOTP code |
| 401 | `invalid_token` | Invalid or expired renew token |
| 403 | `forbidden` | Invalid admin token |
| 403 | `policy_violation` | Request violates signing policy |
| 409 | `user_exists` | User already exists |
| 429 | `rate_limit_exceeded` | Too many requests |
| 500 | `internal_error` | Server internal error |

---

## Public Endpoints

### 1. Get CA Public Key

Download the CA public key for configuring `TrustedUserCAKeys` on servers.

**Endpoint:** `GET /v1/ca/user`

**Authentication:** None

**Response:**
- **Content-Type:** `text/plain; charset=utf-8`
- **Body:** SSH public key in OpenSSH format

**Example:**

```bash
curl https://ca.example.com/v1/ca/user
```

**Response:**
```
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAbCdEfGhIjKlMnOpQrStUvWxYz... user_ca@ca-server
```

**Use Case:**
```bash
# Download and install CA public key on server
curl -fsSL https://ca.example.com/v1/ca/user | sudo tee /etc/ssh/ssh_user_ca.pub
```

---

### 2. Get Server Bootstrap Script

Download the server bootstrap script for automated server configuration.

**Endpoint:** `GET /v1/bootstrap/server.sh`

**Authentication:** None

**Response:**
- **Content-Type:** `text/x-shellscript; charset=utf-8`
- **Body:** Bash script

**Example:**

```bash
# Download and execute (requires root)
curl -fsSL https://ca.example.com/v1/bootstrap/server.sh | sudo bash
```

**Script Actions:**
1. Downloads CA public key
2. Configures `sshd_config` with `TrustedUserCAKeys`
3. Reloads sshd service
4. Registers server with CA

---

### 3. Get Client Bootstrap Script

Download the client bootstrap script for automated client setup.

**Endpoint:** `GET /v1/bootstrap/client.sh`

**Authentication:** None

**Response:**
- **Content-Type:** `text/x-shellscript; charset=utf-8`
- **Body:** Bash script

**Example:**

```bash
# Download and execute
curl -fsSL https://ca.example.com/v1/bootstrap/client.sh | bash
```

**Script Actions:**
1. Prompts for username, password, TOTP
2. Generates SSH key if not exists
3. Requests certificate from CA
4. Saves certificate and renew token
5. Configures SSH client

---

### 4. Register Server

Register a server with the CA (typically called by bootstrap script).

**Endpoint:** `POST /v1/register/server`

**Authentication:** None (public endpoint)

**Request Body:**

```json
{
  "hostname": "web-01",
  "os": "Ubuntu 22.04",
  "kernel": "Linux 6.8.0-40-generic",
  "arch": "x86_64",
  "ip_addresses": ["10.0.1.10", "192.168.1.50"],
  "ssh_version": "OpenSSH_9.6p1",
  "ansible_user": "ansible",
  "ansible_pubkey": "ssh-ed25519 AAAAC3Nz... ansible@web-01",
  "labels": ["prod", "web"],
  "ca_trusted": true
}
```

**Response:**

```json
{
  "status": "ok",
  "server_id": "123",
  "next_actions": []
}
```

**Example:**

```bash
curl -X POST https://ca.example.com/v1/register/server \
  -H "Content-Type: application/json" \
  -d '{
    "hostname": "web-01",
    "os": "Ubuntu 22.04",
    "kernel": "Linux 6.8.0-40-generic",
    "arch": "x86_64",
    "ip_addresses": ["10.0.1.10"],
    "ssh_version": "OpenSSH_9.6p1",
    "ca_trusted": true
  }'
```

---

### 5. Health Check

Check server health status.

**Endpoint:** `GET /health`

**Authentication:** None

**Response:**

```json
{
  "status": "ok"
}
```

**Example:**

```bash
curl https://ca.example.com/health
```

---

## User Endpoints

### 1. Issue Certificate

Issue a new SSH certificate (first-time authentication).

**Endpoint:** `POST /v1/certs/issue`

**Authentication:** Username + Password + TOTP (in request body)

**Request Body:**

```json
{
  "username": "alice",
  "password": "user-password",
  "totp": "123456",
  "public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... alice@laptop",
  "client_hostname": "alice-laptop",
  "requested_principals": ["alice"],
  "requested_validity": "24h"
}
```

**Request Fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `username` | string | Yes | Username |
| `password` | string | Yes | User password |
| `totp` | string | Yes | 6-digit TOTP code |
| `public_key` | string | Yes | SSH public key (OpenSSH format) |
| `client_hostname` | string | No | Client hostname |
| `requested_principals` | array | Yes | Must contain exactly one principal matching username |
| `requested_validity` | string | No | Validity period (e.g., "24h", "48h"). Defaults to configured default. |

**Response:**

```json
{
  "certificate": "ssh-ed25519-cert-v01@openssh.com AAAAC3NzaC1lZDI1NTE5LWNlcnQtdjAxQG9w...",
  "valid_from": "2025-11-15T10:00:00Z",
  "valid_to": "2025-11-16T10:00:00Z",
  "principal": "alice",
  "serial_number": 12345,
  "renew_token": "AbCdEf123456..."
}
```

**Response Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `certificate` | string | Signed SSH certificate (save as `~/.ssh/id_ed25519-cert.pub`) |
| `valid_from` | string | Certificate valid from (ISO 8601) |
| `valid_to` | string | Certificate valid until (ISO 8601) |
| `principal` | string | Certificate principal |
| `serial_number` | integer | Certificate serial number |
| `renew_token` | string | Token for certificate renewal (save securely!) |

**Example:**

```bash
curl -X POST https://ca.example.com/v1/certs/issue \
  -H "Content-Type: application/json" \
  -d '{
    "username": "alice",
    "password": "secret",
    "totp": "123456",
    "public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... alice@laptop",
    "client_hostname": "laptop",
    "requested_principals": ["alice"],
    "requested_validity": "24h"
  }'
```

**Validation Rules:**

- Principal must match username
- Daily certificate limit enforced (default: 10/day)
- Validity period capped at max (default: 48h)
- TOTP code must be valid (±1 time window)

---

### 2. Renew Certificate

Renew an existing certificate using a renew token.

**Endpoint:** `POST /v1/certs/renew`

**Authentication:** Renew token (in request body)

**Request Body:**

```json
{
  "username": "alice",
  "public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... alice@laptop",
  "renew_token": "AbCdEf123456...",
  "current_cert": "ssh-ed25519-cert-v01@openssh.com AAAAC3Nz...",
  "requested_validity": "24h"
}
```

**Request Fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `username` | string | Yes | Username |
| `public_key` | string | Yes | SSH public key (must match token) |
| `renew_token` | string | Yes | Renew token from previous issue/renew |
| `current_cert` | string | No | Current certificate (optional) |
| `requested_validity` | string | No | Validity period (defaults to 24h) |

**Response:**

```json
{
  "certificate": "ssh-ed25519-cert-v01@openssh.com AAAAC3NzaC1lZDI1NTE5LWNlcnQtdjAxQG9w...",
  "valid_from": "2025-11-16T10:00:00Z",
  "valid_to": "2025-11-17T10:00:00Z",
  "principal": "alice",
  "serial_number": 12346
}
```

**Example:**

```bash
curl -X POST https://ca.example.com/v1/certs/renew \
  -H "Content-Type: application/json" \
  -d '{
    "username": "alice",
    "public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... alice@laptop",
    "renew_token": "AbCdEf123456...",
    "requested_validity": "24h"
  }'
```

**Validation Rules:**

- Renew token must be valid and not expired
- Public key fingerprint must match token
- User account must be enabled
- Daily certificate limit still applies

---

## Admin Endpoints

### 1. Create User

Create a new user account.

**Endpoint:** `POST /v1/admin/users`

**Authentication:** Admin token (via `X-Admin-Token` header)

**Request Body:**

```json
{
  "username": "alice",
  "password": "initial-password",
  "totp_secret": "JBSWY3DPEHPK3PXP",
  "enabled": true,
  "max_certs_per_day": 10
}
```

**Request Fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `username` | string | Yes | Username (unique) |
| `password` | string | Yes | Initial password |
| `totp_secret` | string | Yes | TOTP secret (Base32 encoded) |
| `enabled` | boolean | No | Enable account (default: true) |
| `max_certs_per_day` | integer | No | Daily cert limit (default: 10) |

**Response:**

```json
{
  "status": "ok",
  "user_id": 123,
  "totp_qr_url": "otpauth://totp/SSH-CA:alice?secret=JBSWY3DPEHPK3PXP&issuer=SSH-CA"
}
```

**Example:**

```bash
curl -X POST https://ca.example.com/v1/admin/users \
  -H "X-Admin-Token: your-admin-token" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "alice",
    "password": "secret123",
    "totp_secret": "JBSWY3DPEHPK3PXP",
    "enabled": true,
    "max_certs_per_day": 10
  }'
```

**TOTP Secret Generation:**

You can generate a TOTP secret using the admin CLI:

```bash
./bin/admin user create --username alice --password secret --generate-totp
```

---

## Rate Limiting

Rate limiting is configurable in `config.yaml`:

```yaml
rate_limit:
  enabled: true
  requests_per_minute: 60
```

When rate limit is exceeded:

**Response:**
```json
{
  "error": "rate_limit_exceeded",
  "message": "Too many requests, please try again later"
}
```

**HTTP Status:** 429 Too Many Requests

---

## Examples

### Complete Client Setup Flow

```bash
#!/bin/bash

# 1. Generate SSH key
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519_ca -N "" -C "alice@laptop"

# 2. Request certificate
PUBKEY=$(cat ~/.ssh/id_ed25519_ca.pub)
RESPONSE=$(curl -X POST https://ca.example.com/v1/certs/issue \
  -H "Content-Type: application/json" \
  -d "{
    \"username\": \"alice\",
    \"password\": \"secret\",
    \"totp\": \"123456\",
    \"public_key\": \"$PUBKEY\",
    \"client_hostname\": \"$(hostname)\",
    \"requested_principals\": [\"alice\"],
    \"requested_validity\": \"24h\"
  }")

# 3. Extract certificate and token
echo "$RESPONSE" | jq -r '.certificate' > ~/.ssh/id_ed25519_ca-cert.pub
echo "$RESPONSE" | jq -r '.renew_token' > ~/.ssh/ssh_ca_renew_token
chmod 600 ~/.ssh/ssh_ca_renew_token

# 4. Configure SSH
cat >> ~/.ssh/config << EOF
Host myserver
    HostName myserver.example.com
    User alice
    IdentityFile ~/.ssh/id_ed25519_ca
    IdentitiesOnly yes
EOF

# 5. Test connection
ssh myserver
```

### Automatic Certificate Renewal Script

```bash
#!/bin/bash
# Save as ~/.ssh/renew_cert.sh

set -euo pipefail

API_URL="https://ca.example.com"
KEY_FILE="$HOME/.ssh/id_ed25519_ca"
CERT_FILE="$HOME/.ssh/id_ed25519_ca-cert.pub"
TOKEN_FILE="$HOME/.ssh/ssh_ca_renew_token"
USER_NAME="alice"

# Check if certificate needs renewal (< 12 hours remaining)
if ssh-keygen -L -f "$CERT_FILE" 2>/dev/null | grep -q "Valid:"; then
    VALID_TO=$(ssh-keygen -L -f "$CERT_FILE" 2>/dev/null | grep "Valid:" | sed -E 's/.*to ([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}).*/\1/')
    EXPIRY_TS=$(date -d "$VALID_TO" +%s 2>/dev/null || date -j -f "%Y-%m-%dT%H:%M:%S" "$VALID_TO" +%s)
    NOW_TS=$(date +%s)
    THRESHOLD=43200  # 12 hours

    if [ $((EXPIRY_TS - NOW_TS)) -gt $THRESHOLD ]; then
        echo "Certificate still valid, no renewal needed."
        exit 0
    fi
fi

# Renew certificate
if [ ! -f "$TOKEN_FILE" ]; then
    echo "Error: Renew token not found"
    exit 1
fi

PUBKEY=$(cat "$KEY_FILE.pub")
TOKEN=$(cat "$TOKEN_FILE")

curl -fsSL -X POST "$API_URL/v1/certs/renew" \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"$USER_NAME\",\"public_key\":\"$PUBKEY\",\"renew_token\":\"$TOKEN\",\"requested_validity\":\"24h\"}" \
  | jq -r '.certificate' > "$CERT_FILE.new"

mv "$CERT_FILE.new" "$CERT_FILE"
echo "Certificate renewed successfully"
```

**Add to crontab:**

```bash
# Check every 30 minutes
*/30 * * * * $HOME/.ssh/renew_cert.sh >> $HOME/.ssh/renew.log 2>&1
```

---

## Security Considerations

1. **Always use HTTPS** - Never use HTTP in production
2. **Protect renew tokens** - Store with 600 permissions
3. **Rotate admin token** - Change default admin token
4. **Monitor audit logs** - Check for suspicious activity
5. **Limit certificate validity** - Use short validity periods (24h recommended)
6. **Enable rate limiting** - Prevent brute force attacks
7. **Secure CA private key** - File permissions 600, dedicated user

---

## API Versioning

All endpoints are versioned under `/v1/`. Future versions will use `/v2/`, etc.

Current version: **v1**

---

## Support

For issues or questions:
- Check audit logs: `./bin/admin audit list`
- Review server logs
- Consult [deployment guide](deployment.md)
