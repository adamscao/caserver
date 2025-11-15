.PHONY: build test clean install run lint fmt vet dev help

# Build variables
BINARY_NAME=caserver
ADMIN_BINARY=admin
BUILD_DIR=bin
GO=go
GOFLAGS=-v

# Version info
VERSION?=dev
COMMIT=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME=$(shell date -u '+%Y-%m-%d_%H:%M:%S')
LDFLAGS=-ldflags "-X main.Version=$(VERSION) -X main.Commit=$(COMMIT) -X main.BuildTime=$(BUILD_TIME)"

help: ## Display this help screen
	@grep -h -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

build: ## Build the application
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	$(GO) build $(GOFLAGS) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/caserver
	@echo "Building $(ADMIN_BINARY)..."
	$(GO) build $(GOFLAGS) $(LDFLAGS) -o $(BUILD_DIR)/$(ADMIN_BINARY) ./cmd/admin
	@echo "Build complete!"

build-linux: ## Build for Linux
	@echo "Building for Linux..."
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 $(GO) build $(GOFLAGS) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 ./cmd/caserver
	GOOS=linux GOARCH=amd64 $(GO) build $(GOFLAGS) $(LDFLAGS) -o $(BUILD_DIR)/$(ADMIN_BINARY)-linux-amd64 ./cmd/admin

test: ## Run tests
	$(GO) test -v -race -coverprofile=coverage.out ./...

test-coverage: test ## Run tests with coverage
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

clean: ## Clean build artifacts
	@echo "Cleaning..."
	@rm -rf $(BUILD_DIR)
	@rm -f coverage.out coverage.html
	@echo "Clean complete!"

install: build ## Install binaries to /usr/local/bin
	@echo "Installing binaries..."
	install -m 755 $(BUILD_DIR)/$(BINARY_NAME) /usr/local/bin/
	install -m 755 $(BUILD_DIR)/$(ADMIN_BINARY) /usr/local/bin/
	@echo "Installation complete!"

run: ## Run the application (dev mode)
	$(GO) run ./cmd/caserver -config configs/config.yaml.example

dev: ## Run with hot reload (requires air: go install github.com/cosmtrek/air@latest)
	air

lint: ## Run golangci-lint
	golangci-lint run ./...

fmt: ## Format code
	$(GO) fmt ./...

vet: ## Run go vet
	$(GO) vet ./...

tidy: ## Tidy go modules
	$(GO) mod tidy

deps: ## Download dependencies
	$(GO) mod download

upgrade-deps: ## Upgrade all dependencies
	$(GO) get -u ./...
	$(GO) mod tidy

# Development helpers
init-db: ## Initialize database (for development)
	@mkdir -p tmp
	@rm -f tmp/caserver.db
	@echo "Database initialized at tmp/caserver.db"

generate-key: ## Generate test CA key pair
	@mkdir -p tmp
	ssh-keygen -t ed25519 -f tmp/ssh_user_ca -N "" -C "test-ca"
	@echo "Test CA key pair generated at tmp/ssh_user_ca"

.DEFAULT_GOAL := help
