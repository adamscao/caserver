# SSH CA Server

A centralized SSH certificate signing service with automatic renewal capabilities.

## Overview

This project provides a unified SSH user certificate signing service that:

- Issues SSH certificates through HTTP/HTTPS API
- Supports automatic certificate renewal
- Integrates with TOTP for secure authentication
- Provides bootstrap scripts for server and client setup
- Maintains audit logs for all certificate operations

## Features

- **Certificate Signing**: Issue SSH user certificates with configurable validity periods
- **Auto-Renewal**: Clients can automatically renew certificates before expiration
- **Multi-Factor Auth**: Username + password + TOTP for initial certificate issuance
- **Server Registration**: Easy onboarding for new servers via bootstrap script
- **Client Setup**: One-command client configuration
- **Audit Logging**: Complete audit trail stored in SQLite
- **RESTful API**: Clean HTTP API with version support

## Quick Start

### Prerequisites

- Go 1.21 or later
- SQLite 3

### Build

```bash
make build
```

### Run (Development)

```bash
# Create example config
cp configs/config.yaml.example config.yaml

# Edit config.yaml with your settings

# Run the server
make run
```

### Create Admin User

```bash
./bin/admin user create \
  --username admin \
  --password yourpassword \
  --generate-totp
```

## Configuration

See `configs/config.yaml.example` for full configuration options.

Key configuration areas:
- Server listen address
- Database path
- CA key paths
- Certificate policies (validity, limits)
- Admin token

Environment variables:
- `SSH_CA_DB_PATH`: Database file path
- `SSH_CA_PRIVATE_KEY`: CA private key path
- `SSH_CA_ADMIN_TOKEN`: Admin authentication token
- `SSH_CA_LISTEN_ADDR`: Server listen address

## API Endpoints

### Public Endpoints

- `GET /v1/ca/user` - Download CA public key
- `GET /v1/bootstrap/server.sh` - Server bootstrap script
- `GET /v1/bootstrap/client.sh` - Client bootstrap script
- `POST /v1/register/server` - Register a server

### User Endpoints

- `POST /v1/certs/issue` - Issue new certificate (requires username+password+TOTP)
- `POST /v1/certs/renew` - Renew certificate (requires renew_token)

### Admin Endpoints

- `POST /v1/admin/users` - Create user (requires X-Admin-Token header)

## Documentation

- [Requirements](requirement.txt) - Detailed requirements specification
- [Architecture](architecture.md) - System architecture and design
- [Database Schema](database_schema.md) - Database structure and queries

## Development

### Run Tests

```bash
make test
```

### Format Code

```bash
make fmt
```

### Lint

```bash
make lint
```

### Build for Production

```bash
make build-linux
```

## Deployment

See [Architecture Documentation](architecture.md) for deployment guidelines.

Recommended setup:
- Nginx as HTTPS frontend (reverse proxy)
- systemd service for auto-restart
- Regular database backups

## License

See [LICENSE](LICENSE) file.

## Security

- CA private keys are stored with 600 permissions
- Passwords hashed with Argon2id
- TOTP secrets encrypted at rest
- All operations logged for audit
- TLS required for all API endpoints (via Nginx)

## Contributing

This is currently a private project. For questions or issues, contact the maintainer.
