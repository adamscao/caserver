# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased] - 2025-11-16

### Fixed

#### Critical Fixes

- **SSH Certificate Extensions**: Added standard SSH certificate extensions to enable full shell access
  - Added `permit-pty` - allows PTY allocation for interactive shells
  - Added `permit-agent-forwarding` - enables SSH agent forwarding
  - Added `permit-port-forwarding` - enables port forwarding
  - Added `permit-X11-forwarding` - enables X11 forwarding
  - Added `permit-user-rc` - allows execution of user RC files
  - **Impact**: Users can now access interactive shells, not just execute commands

- **JSON Certificate Format**: Fixed certificate string format in API responses
  - Removed trailing newline from certificate strings using `bytes.TrimSpace()`
  - Certificates now parse correctly with `jq` and other JSON tools
  - **Impact**: Client scripts can now reliably parse certificate responses

- **CA Key Loading**: Fixed critical bug in loading existing CA private keys
  - Rewrote `loadKeyPair()` to properly parse PEM-encoded keys (PKCS8 and PKCS1)
  - Fixed panic: "interface conversion: *ssh.wrappedSigner is not ssh.CryptoPublicKey"
  - **Impact**: Service can now restart without regenerating CA keys

#### Client Bootstrap Script

- **JSON Parsing**: Improved certificate extraction from API responses
  - Added support for both `jq` and `python3` JSON parsers
  - Added fallback mechanism if `jq` is not available
  - Used `printf` instead of `echo` to preserve exact certificate format
  - Added validation to ensure certificate was successfully extracted

### Added

#### Diagnostic Tools

- Added `scripts/diagnose-server.sh` - Server-side diagnostic script
  - Checks sshd configuration
  - Verifies CA public key
  - Tests sshd configuration validity
  - Shows authentication logs

- Added `scripts/diagnose-client.sh` - Client-side diagnostic script
  - Checks SSH key files
  - Validates certificate format and validity
  - Tests SSH connection with verbose output
  - Verifies renew token

- Added `scripts/fix-server-sshd.sh` - Automated server configuration fix
  - Properly configures TrustedUserCAKeys
  - Enables PublicKey authentication
  - Tests and reloads sshd safely

### Changed

- Updated `go.mod` and `go.sum` with latest dependencies
- Modified client bootstrap script to handle JSON parsing more robustly

### Security

- Increased default daily certificate limit from 10 to 50 for adams user
- All certificate operations continue to require proper authentication (TOTP + password for issue, renew_token for renewal)

### Testing

- Verified end-to-end certificate workflow:
  - Certificate issuance with username+password+TOTP ✓
  - Certificate renewal with renew_token ✓
  - SSH authentication using certificates ✓
  - Interactive shell access with PTY ✓
  - JSON parsing with jq and python3 ✓

## [Initial Release] - 2025-11-15

### Added

- Initial implementation of SSH CA Server
- HTTP API for certificate issuance and renewal
- User management via admin CLI
- TOTP-based authentication
- Server and client bootstrap scripts
- SQLite database for audit logs and certificate tracking
- Nginx reverse proxy configuration
- SSL/TLS support via Let's Encrypt
- Automatic certificate renewal functionality
- Server registration system
