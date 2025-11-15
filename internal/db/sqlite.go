package db

import (
	"database/sql"
	"fmt"
	"path/filepath"

	_ "github.com/mattn/go-sqlite3"
)

// DB wraps a SQLite database connection
type DB struct {
	*sql.DB
}

// New creates a new database connection
func New(path string) (*DB, error) {
	// Ensure parent directory exists
	dir := filepath.Dir(path)
	if dir != "." && dir != "/" {
		// Note: In production, the directory should be created by deployment scripts
		// with proper permissions
	}

	// Open database with recommended pragmas
	dsn := fmt.Sprintf("%s?_journal_mode=WAL&_synchronous=NORMAL&_cache_size=-64000&_temp_store=MEMORY&_foreign_keys=ON", path)

	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Test connection
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	// Set connection pool settings
	db.SetMaxOpenConns(1) // SQLite works best with single writer
	db.SetMaxIdleConns(1)

	return &DB{DB: db}, nil
}

// Close closes the database connection
func (db *DB) Close() error {
	return db.DB.Close()
}

// BeginTx starts a transaction
func (db *DB) BeginTx() (*sql.Tx, error) {
	return db.DB.Begin()
}
