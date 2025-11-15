# SSH CA Server Deployment Guide

This guide walks you through deploying the SSH CA Server in a production environment.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Server Setup](#server-setup)
3. [Installation](#installation)
4. [Configuration](#configuration)
5. [Nginx Setup](#nginx-setup)
6. [SSL/TLS Certificates](#ssltls-certificates)
7. [Service Management](#service-management)
8. [Initial User Setup](#initial-user-setup)
9. [Backup Strategy](#backup-strategy)
10. [Monitoring](#monitoring)
11. [Security Hardening](#security-hardening)
12. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### System Requirements

- **OS:** Oracle Linux 9.6, CentOS 9, RHEL 9, Ubuntu 22.04+, or similar
- **CPU:** 1 core minimum (2+ cores recommended)
- **RAM:** 512MB minimum (1GB+ recommended)
- **Disk:** 10GB minimum (for logs and database)
- **Go:** Version 1.21 or later (for building from source)

### Network Requirements

- Static IP address or DNS name
- Port 443 (HTTPS) accessible from clients
- Port 2025 (internal) for the Go service (localhost only)

### Dependencies

```bash
# Oracle Linux 9 / RHEL 9 / CentOS 9
sudo dnf install -y git golang nginx certbot sqlite

# Ubuntu 22.04+
sudo apt update
sudo apt install -y git golang nginx certbot sqlite3
```

---

## Server Setup

### 1. Create Dedicated User

```bash
# Create ssh-ca user and group
sudo useradd -r -s /bin/false -m -d /var/lib/ssh-ca ssh-ca

# Create necessary directories
sudo mkdir -p /etc/ssh-ca
sudo mkdir -p /var/lib/ssh-ca
sudo mkdir -p /etc/ssl/ssh-ca
sudo mkdir -p /var/log/ssh-ca

# Set ownership
sudo chown -R ssh-ca:ssh-ca /var/lib/ssh-ca
sudo chown -R ssh-ca:ssh-ca /etc/ssl/ssh-ca
sudo chown -R ssh-ca:ssh-ca /var/log/ssh-ca
```

### 2. Clone Repository

```bash
cd /opt
sudo git clone https://github.com/adamscao/caserver.git
cd caserver
```

### 3. Build Binaries

```bash
# Build for production
sudo make build-linux

# Install binaries
sudo make install

# Verify installation
/usr/local/bin/caserver --version
/usr/local/bin/admin --version
```

---

## Installation

### Option 1: Build from Source (Recommended)

```bash
# Clone repository
cd /opt
sudo git clone https://github.com/adamscao/caserver.git
cd caserver

# Build
sudo make build

# Install binaries
sudo install -m 755 bin/caserver /usr/local/bin/
sudo install -m 755 bin/admin /usr/local/bin/
```

### Option 2: Pre-built Binaries

```bash
# Download pre-built binaries (if available)
wget https://github.com/adamscao/caserver/releases/download/v1.0.0/caserver-linux-amd64
wget https://github.com/adamscao/caserver/releases/download/v1.0.0/admin-linux-amd64

# Install
sudo install -m 755 caserver-linux-amd64 /usr/local/bin/caserver
sudo install -m 755 admin-linux-amd64 /usr/local/bin/admin
```

---

## Configuration

### 1. Create Configuration File

```bash
sudo cp /opt/caserver/configs/config.yaml.example /etc/ssh-ca/config.yaml
sudo chown ssh-ca:ssh-ca /etc/ssh-ca/config.yaml
sudo chmod 600 /etc/ssh-ca/config.yaml
```

### 2. Edit Configuration

```bash
sudo vi /etc/ssh-ca/config.yaml
```

**Important settings to change:**

```yaml
# Server settings
server:
  listen_addr: "127.0.0.1:2025"  # Localhost only (Nginx will proxy)

# Database configuration
database:
  path: "/var/lib/ssh-ca/caserver.db"

# CA key configuration
ca:
  private_key_path: "/etc/ssl/ssh-ca/ssh_user_ca"
  public_key_path: "/etc/ssl/ssh-ca/ssh_user_ca.pub"
  key_type: "ed25519"

# Certificate signing policy
policy:
  default_validity: "24h"
  max_validity: "48h"
  max_certs_per_day: 10

# Renew token configuration
renew_token:
  validity: "90d"

# Admin configuration - IMPORTANT: Change this!
admin:
  token: "REPLACE_WITH_RANDOM_TOKEN"

# Encryption configuration - IMPORTANT: Change this!
encryption:
  key: "REPLACE_WITH_64_HEX_CHARS"

# Logging configuration
logging:
  level: "info"
  format: "json"
```

### 3. Generate Secure Tokens

```bash
# Generate admin token (64 hex chars = 32 bytes)
ADMIN_TOKEN=$(openssl rand -hex 32)
echo "Admin Token: $ADMIN_TOKEN"

# Generate encryption key (64 hex chars = 32 bytes)
ENCRYPTION_KEY=$(openssl rand -hex 32)
echo "Encryption Key: $ENCRYPTION_KEY"

# Update config file
sudo sed -i "s/your-secure-admin-token-change-me-in-production/$ADMIN_TOKEN/" /etc/ssh-ca/config.yaml
sudo sed -i "s/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef/$ENCRYPTION_KEY/" /etc/ssh-ca/config.yaml
```

**IMPORTANT:** Save these tokens securely! You'll need the admin token to create users.

### 4. Set Environment Variables (Optional)

```bash
# Create environment file
sudo tee /etc/ssh-ca/env << EOF
SSH_CA_ADMIN_TOKEN=$ADMIN_TOKEN
SSH_CA_ENCRYPTION_KEY=$ENCRYPTION_KEY
EOF

sudo chown ssh-ca:ssh-ca /etc/ssh-ca/env
sudo chmod 600 /etc/ssh-ca/env
```

---

## Nginx Setup

### 1. Install Nginx

```bash
# Oracle Linux 9 / RHEL 9
sudo dnf install -y nginx

# Ubuntu
sudo apt install -y nginx
```

### 2. Create Nginx Configuration

```bash
sudo cp /opt/caserver/deployments/nginx/nginx.conf.example /etc/nginx/sites-available/ssh-ca
```

Edit the configuration:

```bash
sudo vi /etc/nginx/sites-available/ssh-ca
```

**Configuration file:** (See detailed config in next section)

### 3. Enable Site

```bash
# Ubuntu/Debian
sudo ln -s /etc/nginx/sites-available/ssh-ca /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default

# Oracle Linux/RHEL (if using sites-available pattern)
sudo mkdir -p /etc/nginx/sites-{available,enabled}
# Add to /etc/nginx/nginx.conf: include /etc/nginx/sites-enabled/*;
sudo ln -s /etc/nginx/sites-available/ssh-ca /etc/nginx/sites-enabled/
```

### 4. Test Configuration

```bash
sudo nginx -t
```

---

## SSL/TLS Certificates

### Option 1: Let's Encrypt (Recommended)

```bash
# Install certbot
sudo dnf install -y certbot python3-certbot-nginx  # Oracle Linux/RHEL
# sudo apt install -y certbot python3-certbot-nginx  # Ubuntu

# Stop nginx temporarily
sudo systemctl stop nginx

# Obtain certificate
sudo certbot certonly --standalone -d ca.example.com

# Certificates will be in:
# /etc/letsencrypt/live/ca.example.com/fullchain.pem
# /etc/letsencrypt/live/ca.example.com/privkey.pem

# Setup auto-renewal
sudo systemctl enable --now certbot-renew.timer
```

### Option 2: Self-Signed Certificate (Testing Only)

```bash
sudo mkdir -p /etc/nginx/ssl
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout /etc/nginx/ssl/ssh-ca.key \
  -out /etc/nginx/ssl/ssh-ca.crt \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=ca.example.com"
```

### 3. Update Nginx SSL Paths

Edit `/etc/nginx/sites-available/ssh-ca` and update SSL certificate paths.

---

## Service Management

### 1. Create systemd Service

```bash
sudo cp /opt/caserver/scripts/systemd/ssh-ca.service /etc/systemd/system/
```

**Service file content:**

```ini
[Unit]
Description=SSH CA Server
Documentation=https://github.com/adamscao/caserver
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=ssh-ca
Group=ssh-ca
ExecStart=/usr/local/bin/caserver -config /etc/ssh-ca/config.yaml
Restart=on-failure
RestartSec=5s

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/ssh-ca /etc/ssl/ssh-ca /var/log/ssh-ca
CapabilityBoundingSet=
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=ssh-ca

[Install]
WantedBy=multi-user.target
```

### 2. Enable and Start Services

```bash
# Reload systemd
sudo systemctl daemon-reload

# Enable services to start on boot
sudo systemctl enable ssh-ca
sudo systemctl enable nginx

# Start services
sudo systemctl start ssh-ca
sudo systemctl start nginx

# Check status
sudo systemctl status ssh-ca
sudo systemctl status nginx
```

### 3. View Logs

```bash
# SSH CA Server logs
sudo journalctl -u ssh-ca -f

# Nginx access logs
sudo tail -f /var/log/nginx/ssh-ca-access.log

# Nginx error logs
sudo tail -f /var/log/nginx/ssh-ca-error.log
```

---

## Initial User Setup

### 1. Create First Admin User

```bash
sudo -u ssh-ca /usr/local/bin/admin user create \
  --config /etc/ssh-ca/config.yaml \
  --username admin \
  --password "ChangeMe123!" \
  --generate-totp \
  --enabled \
  --max-certs-per-day 20
```

**Output:**
```
User created successfully!
User ID: 1
Username: admin
Enabled: true
Max certs per day: 20

TOTP Secret: JBSWY3DPEHPK3PXP
TOTP QR URL: otpauth://totp/SSH-CA:admin?secret=JBSWY3DPEHPK3PXP&issuer=SSH-CA

Scan the QR URL with a TOTP app (Google Authenticator, Authy, etc.)
```

### 2. Setup TOTP

1. Install a TOTP app on your phone (Google Authenticator, Authy, etc.)
2. Scan the QR code URL or manually enter the secret
3. Test the TOTP code

### 3. Create Regular Users

```bash
# Create users via API
curl -X POST https://ca.example.com/v1/admin/users \
  -H "X-Admin-Token: $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "alice",
    "password": "initial-password",
    "totp_secret": "GENERATED_SECRET",
    "enabled": true,
    "max_certs_per_day": 10
  }'
```

### 4. Test Certificate Issuance

```bash
# On client machine
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519_ca -N ""

# Request certificate
PUBKEY=$(cat ~/.ssh/id_ed25519_ca.pub)
curl -X POST https://ca.example.com/v1/certs/issue \
  -H "Content-Type: application/json" \
  -d "{
    \"username\": \"admin\",
    \"password\": \"ChangeMe123!\",
    \"totp\": \"123456\",
    \"public_key\": \"$PUBKEY\",
    \"requested_principals\": [\"admin\"],
    \"requested_validity\": \"24h\"
  }"
```

---

## Backup Strategy

### 1. Database Backup

```bash
#!/bin/bash
# Save as /usr/local/bin/backup-ssh-ca.sh

BACKUP_DIR="/var/backups/ssh-ca"
DB_PATH="/var/lib/ssh-ca/caserver.db"
DATE=$(date +%Y%m%d-%H%M%S)

mkdir -p "$BACKUP_DIR"

# Backup database
sqlite3 "$DB_PATH" ".backup '$BACKUP_DIR/caserver-$DATE.db'"

# Backup CA keys
tar czf "$BACKUP_DIR/ssh-ca-keys-$DATE.tar.gz" /etc/ssl/ssh-ca/

# Keep only last 30 days
find "$BACKUP_DIR" -name "*.db" -mtime +30 -delete
find "$BACKUP_DIR" -name "*.tar.gz" -mtime +30 -delete

echo "Backup completed: $DATE"
```

### 2. Setup Automatic Backups

```bash
# Make script executable
sudo chmod +x /usr/local/bin/backup-ssh-ca.sh

# Add to crontab (daily at 2 AM)
sudo crontab -e
```

Add:
```
0 2 * * * /usr/local/bin/backup-ssh-ca.sh >> /var/log/ssh-ca/backup.log 2>&1
```

### 3. Critical Files to Backup

- `/var/lib/ssh-ca/caserver.db` - Database
- `/etc/ssl/ssh-ca/ssh_user_ca` - CA private key (MOST IMPORTANT)
- `/etc/ssl/ssh-ca/ssh_user_ca.pub` - CA public key
- `/etc/ssh-ca/config.yaml` - Configuration

**Store backups securely off-site!**

---

## Monitoring

### 1. Log Rotation

```bash
sudo tee /etc/logrotate.d/ssh-ca << EOF
/var/log/ssh-ca/*.log {
    daily
    rotate 30
    compress
    delaycompress
    notifempty
    create 0640 ssh-ca ssh-ca
    sharedscripts
    postrotate
        /bin/systemctl reload ssh-ca > /dev/null 2>&1 || true
    endscript
}
EOF
```

### 2. Health Monitoring Script

```bash
#!/bin/bash
# Save as /usr/local/bin/check-ssh-ca-health.sh

# Check service status
if ! systemctl is-active --quiet ssh-ca; then
    echo "CRITICAL: SSH CA service is not running"
    exit 2
fi

# Check HTTP endpoint
if ! curl -sf http://localhost:2025/health > /dev/null; then
    echo "CRITICAL: SSH CA health check failed"
    exit 2
fi

# Check HTTPS endpoint (via Nginx)
if ! curl -sf https://ca.example.com/health > /dev/null; then
    echo "WARNING: HTTPS endpoint check failed"
    exit 1
fi

echo "OK: All checks passed"
exit 0
```

### 3. Setup Monitoring (Optional)

Integrate with Nagios, Zabbix, or Prometheus:

```bash
# Add to Nagios/NRPE
command[check_ssh_ca]=/usr/local/bin/check-ssh-ca-health.sh
```

---

## Security Hardening

### 1. Firewall Configuration

```bash
# Oracle Linux/RHEL (firewalld)
sudo firewall-cmd --permanent --add-service=https
sudo firewall-cmd --reload

# Ubuntu (ufw)
sudo ufw allow 443/tcp
sudo ufw enable
```

### 2. SELinux Configuration (Oracle Linux/RHEL)

```bash
# If using SELinux
sudo semanage port -a -t http_port_t -p tcp 2025
sudo setsebool -P httpd_can_network_connect 1

# Allow Nginx to connect to backend
sudo setsebool -P httpd_can_network_relay 1
```

### 3. File Permissions Audit

```bash
# Check CA private key permissions
ls -l /etc/ssl/ssh-ca/ssh_user_ca
# Should be: -rw------- 1 ssh-ca ssh-ca

# Check database permissions
ls -l /var/lib/ssh-ca/caserver.db
# Should be: -rw------- 1 ssh-ca ssh-ca

# Check config permissions
ls -l /etc/ssh-ca/config.yaml
# Should be: -rw------- 1 ssh-ca ssh-ca
```

### 4. Disable Root SSH Access (Optional)

After verifying certificate authentication works:

```bash
sudo vi /etc/ssh/sshd_config
```

Change:
```
PermitRootLogin no
PasswordAuthentication no
```

Reload:
```bash
sudo systemctl reload sshd
```

---

## Troubleshooting

### Service Won't Start

```bash
# Check logs
sudo journalctl -u ssh-ca -n 50

# Check config syntax
/usr/local/bin/caserver -config /etc/ssh-ca/config.yaml

# Check file permissions
sudo -u ssh-ca ls /var/lib/ssh-ca
sudo -u ssh-ca ls /etc/ssl/ssh-ca
```

### Database Errors

```bash
# Check database file
sudo -u ssh-ca sqlite3 /var/lib/ssh-ca/caserver.db ".schema"

# Re-run migrations
sudo systemctl stop ssh-ca
sudo -u ssh-ca /usr/local/bin/caserver -config /etc/ssh-ca/config.yaml
# Wait for migrations, then Ctrl+C
sudo systemctl start ssh-ca
```

### Certificate Signing Fails

```bash
# Check CA keys exist
ls -l /etc/ssl/ssh-ca/

# Regenerate if needed (CAUTION: Invalidates all issued certs!)
sudo rm /etc/ssl/ssh-ca/ssh_user_ca*
sudo systemctl restart ssh-ca

# Check CA public key
curl https://ca.example.com/v1/ca/user
```

### Nginx 502 Bad Gateway

```bash
# Check backend is running
curl http://localhost:2025/health

# Check Nginx error logs
sudo tail -f /var/log/nginx/error.log

# Verify Nginx config
sudo nginx -t

# Restart both services
sudo systemctl restart ssh-ca nginx
```

### TOTP Validation Fails

```bash
# Check system time (TOTP is time-based!)
date
timedatectl

# Sync time
sudo chronyc makestep  # or: sudo ntpdate pool.ntp.org

# Check TOTP secret in database
sudo -u ssh-ca sqlite3 /var/lib/ssh-ca/caserver.db \
  "SELECT username, totp_secret FROM users WHERE username='admin';"
```

---

## Maintenance

### Update CA Server

```bash
# Stop service
sudo systemctl stop ssh-ca

# Backup current version
sudo cp /usr/local/bin/caserver /usr/local/bin/caserver.bak

# Update code
cd /opt/caserver
sudo git pull

# Rebuild
sudo make build

# Reinstall
sudo make install

# Start service
sudo systemctl start ssh-ca

# Verify
sudo systemctl status ssh-ca
curl https://ca.example.com/health
```

### Clean Up Old Data

```bash
# Delete expired tokens (older than 120 days)
sudo -u ssh-ca sqlite3 /var/lib/ssh-ca/caserver.db \
  "DELETE FROM renew_tokens WHERE expires_at < datetime('now', '-120 days');"

# Delete old audit logs (older than 1 year)
sudo -u ssh-ca sqlite3 /var/lib/ssh-ca/caserver.db \
  "DELETE FROM audit_logs WHERE timestamp < datetime('now', '-1 year');"

# Vacuum database
sudo -u ssh-ca sqlite3 /var/lib/ssh-ca/caserver.db "VACUUM;"
```

---

## Production Checklist

- [ ] Change default admin token
- [ ] Change default encryption key
- [ ] Setup SSL/TLS with valid certificate
- [ ] Configure firewall
- [ ] Setup log rotation
- [ ] Setup automated backups
- [ ] Test certificate issuance
- [ ] Test certificate renewal
- [ ] Setup monitoring/alerting
- [ ] Document admin credentials (securely!)
- [ ] Test disaster recovery procedure
- [ ] Configure SELinux/AppArmor (if applicable)
- [ ] Setup fail2ban (optional)
- [ ] Review and test backup restoration

---

## Support

For additional help:
- Review logs: `journalctl -u ssh-ca`
- Check API docs: `docs/api.md`
- View audit logs: `/usr/local/bin/admin audit list`
