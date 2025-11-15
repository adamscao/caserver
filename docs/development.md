# Development Guide

This guide helps developers understand the codebase and contribute to the SSH CA Server project.

---

## Table of Contents

1. [Development Environment](#development-environment)
2. [Project Structure](#project-structure)
3. [Building and Testing](#building-and-testing)
4. [Code Style](#code-style)
5. [Adding Features](#adding-features)
6. [Database Changes](#database-changes)
7. [Testing](#testing)
8. [Debugging](#debugging)

---

## Development Environment

### Prerequisites

- Go 1.21 or later
- SQLite 3
- Git
- Make
- curl (for testing)

### Setup

```bash
# Clone repository
git clone https://github.com/adamscao/caserver.git
cd caserver

# Install dependencies
go mod download

# Build
make build

# Run tests
make test
```

### IDE Setup

**VS Code:**

Install recommended extensions:
- Go (golang.go)
- SQLite Viewer

**GoLand/IntelliJ IDEA:**

No additional configuration needed.

---

## Project Structure

```
caserver/
├── cmd/                      # Entry points
│   ├── caserver/            # Main server
│   └── admin/               # Admin CLI
├── internal/                # Private application code
│   ├── api/                 # HTTP layer
│   │   ├── handlers/        # Request handlers
│   │   │   ├── ca.go
│   │   │   ├── certs.go
│   │   │   ├── admin.go
│   │   │   ├── register.go
│   │   │   ├── bootstrap.go
│   │   │   └── response.go
│   │   ├── middleware/      # HTTP middleware
│   │   │   ├── auth.go
│   │   │   └── logger.go
│   │   └── router.go        # Route configuration
│   ├── ca/                  # Certificate authority logic
│   │   ├── keypair.go
│   │   └── signer.go
│   ├── auth/                # Authentication
│   │   ├── password.go
│   │   ├── totp.go
│   │   └── token.go
│   ├── config/              # Configuration
│   │   ├── config.go
│   │   └── loader.go
│   ├── db/                  # Database
│   │   ├── sqlite.go
│   │   ├── migrations.go
│   │   └── repository/      # Data access
│   │       ├── user.go
│   │       ├── cert.go
│   │       ├── token.go
│   │       ├── server.go
│   │       └── audit.go
│   ├── models/              # Data models
│   │   ├── user.go
│   │   ├── cert.go
│   │   ├── token.go
│   │   ├── server.go
│   │   └── audit.go
│   └── policy/              # Business logic
│       └── validator.go
├── pkg/                     # Public libraries
│   └── sshutil/
│       └── fingerprint.go
├── configs/                 # Configuration files
├── scripts/                 # Scripts
├── deployments/             # Deployment configs
└── docs/                    # Documentation
```

### Module Responsibilities

- **cmd/**: Application entry points
- **internal/api/**: HTTP server and routing
- **internal/ca/**: SSH CA operations
- **internal/auth/**: Authentication primitives
- **internal/db/**: Database access and migrations
- **internal/models/**: Data structures
- **internal/policy/**: Business rules
- **pkg/**: Reusable utilities

---

## Building and Testing

### Build Commands

```bash
# Build both binaries
make build

# Build for Linux
make build-linux

# Clean build artifacts
make clean

# Install to /usr/local/bin
sudo make install
```

### Run Development Server

```bash
# Create test config
cp configs/config.yaml.example config.yaml

# Run server
make run

# Or with custom config
go run ./cmd/caserver -config config.yaml
```

### Testing

```bash
# Run all tests
make test

# Run tests with coverage
make test-coverage

# Run specific package
go test -v ./internal/auth/...

# Run with race detector
go test -race ./...
```

---

## Code Style

### Go Conventions

Follow standard Go conventions:

- Use `gofmt` for formatting
- Use `golangci-lint` for linting
- Write godoc comments for exported functions
- Keep functions small and focused

```bash
# Format code
make fmt

# Run linter
make lint

# Vet code
make vet
```

### Naming Conventions

- **Files**: lowercase with underscores (e.g., `cert_handler.go`)
- **Packages**: lowercase, single word (e.g., `package auth`)
- **Types**: PascalCase (e.g., `type UserRepository struct`)
- **Functions**: camelCase for private, PascalCase for exported
- **Constants**: PascalCase or UPPER_SNAKE_CASE

### Error Handling

```go
// Good: Wrap errors with context
if err != nil {
    return fmt.Errorf("failed to create user: %w", err)
}

// Bad: Lose error context
if err != nil {
    return err
}
```

---

## Adding Features

### Adding a New API Endpoint

1. **Define the handler** in `internal/api/handlers/`:

```go
// internal/api/handlers/myfeature.go
package handlers

func (h *MyHandler) HandleRequest(c *gin.Context) {
    // Implementation
}
```

2. **Add route** in `internal/api/router.go`:

```go
v1.GET("/myendpoint", myHandler.HandleRequest)
```

3. **Add tests**:

```go
// internal/api/handlers/myfeature_test.go
func TestHandleRequest(t *testing.T) {
    // Test implementation
}
```

4. **Update documentation** in `docs/api.md`

### Adding a New Database Table

1. **Update migrations** in `internal/db/migrations.go`:

```go
const myNewTable = `
CREATE TABLE my_table (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
)`
```

2. **Add model** in `internal/models/`:

```go
// internal/models/mytable.go
type MyTable struct {
    ID        int64     `json:"id"`
    Name      string    `json:"name"`
    CreatedAt time.Time `json:"created_at"`
}
```

3. **Create repository** in `internal/db/repository/`:

```go
// internal/db/repository/mytable.go
type MyTableRepository struct {
    db *sql.DB
}

func (r *MyTableRepository) Create(item *models.MyTable) error {
    // Implementation
}
```

4. **Update** `database_schema.md`

---

## Database Changes

### Migration Strategy

1. **Never modify existing migrations** - Always create new ones
2. **Use transactions** for migrations
3. **Test rollback** procedures
4. **Increment version number**

```go
// Example migration
func runMigrationV2(db *db.DB) error {
    tx, err := db.BeginTx()
    if err != nil {
        return err
    }
    defer tx.Rollback()

    // Your migration SQL
    _, err = tx.Exec("ALTER TABLE users ADD COLUMN email TEXT")
    if err != nil {
        return err
    }

    _, err = tx.Exec("INSERT INTO schema_version (version) VALUES (2)")
    if err != nil {
        return err
    }

    return tx.Commit()
}
```

### Inspecting Database

```bash
# Open database
sqlite3 tmp/caserver.db

# List tables
.tables

# View schema
.schema users

# Query data
SELECT * FROM users;

# Exit
.quit
```

---

## Testing

### Unit Tests

```go
// Example unit test
func TestHashPassword(t *testing.T) {
    password := "test123"
    hash, err := auth.HashPassword(password)

    assert.NoError(t, err)
    assert.NotEmpty(t, hash)

    valid, err := auth.VerifyPassword(password, hash)
    assert.NoError(t, err)
    assert.True(t, valid)
}
```

### Integration Tests

```go
// Example integration test
func TestCertificateIssuance(t *testing.T) {
    // Setup test database
    db := setupTestDB(t)
    defer db.Close()

    // Create test user
    user := createTestUser(t, db)

    // Test certificate issuance
    cert, err := issueCertificate(user)
    assert.NoError(t, err)
    assert.NotNil(t, cert)
}
```

### Test Helpers

Create test helpers in `internal/testutil/`:

```go
// internal/testutil/database.go
func SetupTestDB(t *testing.T) *db.DB {
    tmpDB := filepath.Join(t.TempDir(), "test.db")
    database, err := db.New(tmpDB)
    require.NoError(t, err)

    err = db.RunMigrations(database)
    require.NoError(t, err)

    return database
}
```

---

## Debugging

### Logging

Use structured logging:

```go
log.Printf("[INFO] User %s authenticated successfully", username)
log.Printf("[ERROR] Failed to sign certificate: %v", err)
log.Printf("[DEBUG] Token hash: %s", tokenHash)
```

### Debug Mode

Run with debug logging:

```yaml
# config.yaml
logging:
  level: "debug"
  format: "json"
```

### Using Delve Debugger

```bash
# Install delve
go install github.com/go-delve/delve/cmd/dlv@latest

# Debug server
dlv debug ./cmd/caserver -- -config config.yaml

# Debug with breakpoint
dlv debug ./cmd/caserver
(dlv) break main.main
(dlv) continue
```

### Common Debug Scenarios

**Database Issues:**

```bash
# Enable SQLite trace
GODEBUG=sqlite3trace=1 go run ./cmd/caserver
```

**HTTP Requests:**

```bash
# Use curl with verbose output
curl -v https://localhost:2025/health

# View request/response
curl -i https://localhost:2025/v1/ca/user
```

**TOTP Issues:**

```go
// Add debug logging
log.Printf("TOTP secret: %s", user.TOTPSecret)
log.Printf("TOTP code: %s", code)
log.Printf("Current time: %v", time.Now())
```

---

## Development Workflow

### Feature Development

1. Create a feature branch:
   ```bash
   git checkout -b feature/my-feature
   ```

2. Make changes and test:
   ```bash
   make build
   make test
   ```

3. Format and lint:
   ```bash
   make fmt
   make lint
   ```

4. Commit changes:
   ```bash
   git add .
   git commit -m "Add my feature"
   ```

5. Push and create PR:
   ```bash
   git push origin feature/my-feature
   ```

### Code Review Checklist

- [ ] Tests added/updated
- [ ] Documentation updated
- [ ] Error handling proper
- [ ] Logging added
- [ ] No hardcoded secrets
- [ ] Database migrations tested
- [ ] API docs updated
- [ ] Code formatted and linted

---

## Useful Commands

```bash
# Format code
go fmt ./...

# Tidy dependencies
go mod tidy

# Update dependencies
go get -u ./...

# Generate CA test key
make generate-key

# Initialize test database
make init-db

# View dependency graph
go mod graph | grep adamscao

# Check for outdated dependencies
go list -u -m all
```

---

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Update documentation
6. Submit a pull request

---

## Resources

- [Go Documentation](https://golang.org/doc/)
- [Gin Framework](https://gin-gonic.com/docs/)
- [SQLite Documentation](https://www.sqlite.org/docs.html)
- [SSH Certificate Format](https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.certkeys)
