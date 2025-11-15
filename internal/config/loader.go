package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Load loads configuration from a YAML file
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return &cfg, nil
}

// LoadWithEnv loads configuration from a file and applies environment variable overrides
func LoadWithEnv(path string) (*Config, error) {
	cfg, err := Load(path)
	if err != nil {
		return nil, err
	}

	// Apply environment variable overrides
	if dbPath := os.Getenv("SSH_CA_DB_PATH"); dbPath != "" {
		cfg.Database.Path = dbPath
	}

	if privateKey := os.Getenv("SSH_CA_PRIVATE_KEY"); privateKey != "" {
		cfg.CA.PrivateKeyPath = privateKey
	}

	if publicKey := os.Getenv("SSH_CA_PUBLIC_KEY"); publicKey != "" {
		cfg.CA.PublicKeyPath = publicKey
	}

	if adminToken := os.Getenv("SSH_CA_ADMIN_TOKEN"); adminToken != "" {
		cfg.Admin.Token = adminToken
	}

	if listenAddr := os.Getenv("SSH_CA_LISTEN_ADDR"); listenAddr != "" {
		cfg.Server.ListenAddr = listenAddr
	}

	if encKey := os.Getenv("SSH_CA_ENCRYPTION_KEY"); encKey != "" {
		cfg.Encryption.Key = encKey
	}

	// Validate again after env overrides
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration after env overrides: %w", err)
	}

	return cfg, nil
}
