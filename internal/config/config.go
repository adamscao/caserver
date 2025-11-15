package config

import (
	"fmt"
	"os"
	"time"
)

// Config holds all configuration for the application
type Config struct {
	Server     ServerConfig     `yaml:"server"`
	Database   DatabaseConfig   `yaml:"database"`
	CA         CAConfig         `yaml:"ca"`
	Policy     PolicyConfig     `yaml:"policy"`
	RenewToken RenewTokenConfig `yaml:"renew_token"`
	Admin      AdminConfig      `yaml:"admin"`
	Encryption EncryptionConfig `yaml:"encryption"`
	Logging    LoggingConfig    `yaml:"logging"`
	RateLimit  RateLimitConfig  `yaml:"rate_limit"`
}

// ServerConfig contains server configuration
type ServerConfig struct {
	ListenAddr string `yaml:"listen_addr"`
}

// DatabaseConfig contains database configuration
type DatabaseConfig struct {
	Path string `yaml:"path"`
}

// CAConfig contains CA key configuration
type CAConfig struct {
	PrivateKeyPath string `yaml:"private_key_path"`
	PublicKeyPath  string `yaml:"public_key_path"`
	KeyType        string `yaml:"key_type"`
}

// PolicyConfig contains certificate signing policy
type PolicyConfig struct {
	DefaultValidity  string `yaml:"default_validity"`
	MaxValidity      string `yaml:"max_validity"`
	MaxCertsPerDay   int    `yaml:"max_certs_per_day"`
}

// RenewTokenConfig contains renew token configuration
type RenewTokenConfig struct {
	Validity string `yaml:"validity"`
}

// AdminConfig contains admin configuration
type AdminConfig struct {
	Token string `yaml:"token"`
}

// EncryptionConfig contains encryption configuration
type EncryptionConfig struct {
	Key string `yaml:"key"`
}

// LoggingConfig contains logging configuration
type LoggingConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

// RateLimitConfig contains rate limiting configuration
type RateLimitConfig struct {
	Enabled           bool `yaml:"enabled"`
	RequestsPerMinute int  `yaml:"requests_per_minute"`
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	// Server validation
	if c.Server.ListenAddr == "" {
		return fmt.Errorf("server.listen_addr is required")
	}

	// Database validation
	if c.Database.Path == "" {
		return fmt.Errorf("database.path is required")
	}

	// CA validation
	if c.CA.PrivateKeyPath == "" {
		return fmt.Errorf("ca.private_key_path is required")
	}
	if c.CA.PublicKeyPath == "" {
		return fmt.Errorf("ca.public_key_path is required")
	}
	if c.CA.KeyType != "ed25519" && c.CA.KeyType != "rsa" {
		return fmt.Errorf("ca.key_type must be 'ed25519' or 'rsa'")
	}

	// Policy validation
	if _, err := time.ParseDuration(c.Policy.DefaultValidity); err != nil {
		return fmt.Errorf("policy.default_validity is invalid: %w", err)
	}
	if _, err := time.ParseDuration(c.Policy.MaxValidity); err != nil {
		return fmt.Errorf("policy.max_validity is invalid: %w", err)
	}
	if c.Policy.MaxCertsPerDay <= 0 {
		return fmt.Errorf("policy.max_certs_per_day must be positive")
	}

	// Renew token validation
	if _, err := parseDuration(c.RenewToken.Validity); err != nil {
		return fmt.Errorf("renew_token.validity is invalid: %w", err)
	}

	// Admin validation
	if c.Admin.Token == "" {
		return fmt.Errorf("admin.token is required")
	}
	if c.Admin.Token == "your-secure-admin-token-change-me-in-production" {
		fmt.Fprintf(os.Stderr, "WARNING: Using default admin token. Please change it in production!\n")
	}

	// Encryption validation
	if len(c.Encryption.Key) != 64 { // 32 bytes = 64 hex chars
		return fmt.Errorf("encryption.key must be 64 hex characters (32 bytes)")
	}

	// Logging validation
	validLogLevels := map[string]bool{"debug": true, "info": true, "warn": true, "error": true}
	if !validLogLevels[c.Logging.Level] {
		return fmt.Errorf("logging.level must be one of: debug, info, warn, error")
	}
	if c.Logging.Format != "json" && c.Logging.Format != "text" {
		return fmt.Errorf("logging.format must be 'json' or 'text'")
	}

	return nil
}

// GetDefaultValidityDuration returns the default validity as time.Duration
func (c *Config) GetDefaultValidityDuration() time.Duration {
	d, _ := time.ParseDuration(c.Policy.DefaultValidity)
	return d
}

// GetMaxValidityDuration returns the max validity as time.Duration
func (c *Config) GetMaxValidityDuration() time.Duration {
	d, _ := time.ParseDuration(c.Policy.MaxValidity)
	return d
}

// GetRenewTokenValidityDuration returns the renew token validity as time.Duration
func (c *Config) GetRenewTokenValidityDuration() time.Duration {
	d, _ := parseDuration(c.RenewToken.Validity)
	return d
}

// parseDuration parses duration with support for days (e.g., "90d")
func parseDuration(s string) (time.Duration, error) {
	// Handle "d" suffix for days
	if len(s) > 1 && s[len(s)-1] == 'd' {
		days := s[:len(s)-1]
		var d int
		if _, err := fmt.Sscanf(days, "%d", &d); err != nil {
			return 0, err
		}
		return time.Duration(d) * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}
