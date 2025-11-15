package db

import (
	"database/sql"
	"fmt"
)

// RunMigrations executes all database migrations
func RunMigrations(db *DB) error {
	// Check if schema_version table exists
	var tableExists bool
	err := db.QueryRow(`
		SELECT COUNT(*) > 0
		FROM sqlite_master
		WHERE type='table' AND name='schema_version'
	`).Scan(&tableExists)
	if err != nil {
		return fmt.Errorf("failed to check schema_version table: %w", err)
	}

	if !tableExists {
		// First time initialization
		if err := initializeSchema(db); err != nil {
			return fmt.Errorf("failed to initialize schema: %w", err)
		}
		return nil
	}

	// Get current version
	var currentVersion int
	err = db.QueryRow(`
		SELECT version FROM schema_version
		ORDER BY applied_at DESC LIMIT 1
	`).Scan(&currentVersion)
	if err != nil {
		return fmt.Errorf("failed to get current schema version: %w", err)
	}

	// Apply migrations if needed
	// Currently only version 1 exists
	if currentVersion < 1 {
		return fmt.Errorf("invalid schema version: %d", currentVersion)
	}

	return nil
}

// initializeSchema creates all tables for a new database
func initializeSchema(db *DB) error {
	tx, err := db.BeginTx()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Schema version table
	if err := execSQL(tx, schemaVersionTable); err != nil {
		return err
	}

	// Users table
	if err := execSQL(tx, usersTable); err != nil {
		return err
	}
	if err := execSQL(tx, usersIndexes); err != nil {
		return err
	}

	// Certificates table
	if err := execSQL(tx, certificatesTable); err != nil {
		return err
	}
	if err := execSQL(tx, certificatesIndexes); err != nil {
		return err
	}

	// Renew tokens table
	if err := execSQL(tx, renewTokensTable); err != nil {
		return err
	}
	if err := execSQL(tx, renewTokensIndexes); err != nil {
		return err
	}

	// Registered servers table
	if err := execSQL(tx, registeredServersTable); err != nil {
		return err
	}
	if err := execSQL(tx, registeredServersIndexes); err != nil {
		return err
	}

	// Audit logs table
	if err := execSQL(tx, auditLogsTable); err != nil {
		return err
	}
	if err := execSQL(tx, auditLogsIndexes); err != nil {
		return err
	}

	// Insert initial schema version
	if err := execSQL(tx, `INSERT INTO schema_version (version) VALUES (1)`); err != nil {
		return err
	}

	return tx.Commit()
}

// execSQL executes a SQL statement
func execSQL(tx *sql.Tx, query string) error {
	_, err := tx.Exec(query)
	return err
}

// Schema definitions
const (
	schemaVersionTable = `
CREATE TABLE schema_version (
    version INTEGER NOT NULL,
    applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
)`

	usersTable = `
CREATE TABLE users (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    username          TEXT NOT NULL UNIQUE,
    password_hash     TEXT NOT NULL,
    totp_secret       TEXT NOT NULL,
    enabled           INTEGER NOT NULL DEFAULT 1,
    max_certs_per_day INTEGER NOT NULL DEFAULT 10,
    created_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
)`

	usersIndexes = `
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_enabled ON users(enabled)`

	certificatesTable = `
CREATE TABLE certificates (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER NOT NULL,
    public_key_fp   TEXT NOT NULL,
    serial_number   INTEGER NOT NULL UNIQUE,
    principal       TEXT NOT NULL,
    valid_from      DATETIME NOT NULL,
    valid_to        DATETIME NOT NULL,
    client_ip       TEXT NOT NULL,
    client_hostname TEXT,
    user_agent      TEXT,
    issued_at       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
)`

	certificatesIndexes = `
CREATE INDEX idx_certs_user_id ON certificates(user_id);
CREATE INDEX idx_certs_serial ON certificates(serial_number);
CREATE INDEX idx_certs_fp ON certificates(public_key_fp);
CREATE INDEX idx_certs_issued_at ON certificates(issued_at);
CREATE INDEX idx_certs_valid_to ON certificates(valid_to)`

	renewTokensTable = `
CREATE TABLE renew_tokens (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER NOT NULL,
    token_hash      TEXT NOT NULL UNIQUE,
    public_key_fp   TEXT NOT NULL,
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at      DATETIME NOT NULL,
    last_used_at    DATETIME,

    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
)`

	renewTokensIndexes = `
CREATE INDEX idx_tokens_user_id ON renew_tokens(user_id);
CREATE INDEX idx_tokens_hash ON renew_tokens(token_hash);
CREATE INDEX idx_tokens_fp ON renew_tokens(public_key_fp);
CREATE INDEX idx_tokens_expires_at ON renew_tokens(expires_at)`

	registeredServersTable = `
CREATE TABLE registered_servers (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    hostname        TEXT NOT NULL,
    os              TEXT,
    kernel          TEXT,
    arch            TEXT,
    ip_addresses    TEXT,
    ssh_version     TEXT,
    ansible_user    TEXT,
    ansible_pubkey  TEXT,
    labels          TEXT,
    ca_trusted      INTEGER NOT NULL DEFAULT 0,
    registered_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
)`

	registeredServersIndexes = `
CREATE INDEX idx_servers_hostname ON registered_servers(hostname);
CREATE INDEX idx_servers_registered_at ON registered_servers(registered_at)`

	auditLogsTable = `
CREATE TABLE audit_logs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    action      TEXT NOT NULL,
    username    TEXT,
    client_ip   TEXT NOT NULL,
    user_agent  TEXT,
    success     INTEGER NOT NULL,
    error_msg   TEXT,
    details     TEXT
)`

	auditLogsIndexes = `
CREATE INDEX idx_audit_timestamp ON audit_logs(timestamp);
CREATE INDEX idx_audit_action ON audit_logs(action);
CREATE INDEX idx_audit_username ON audit_logs(username);
CREATE INDEX idx_audit_success ON audit_logs(success);
CREATE INDEX idx_audit_client_ip ON audit_logs(client_ip)`
)
