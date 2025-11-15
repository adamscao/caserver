package repository

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/adamscao/caserver/internal/models"
)

// ServerRepository handles registered server data access
type ServerRepository struct {
	db *sql.DB
}

// NewServerRepository creates a new server repository
func NewServerRepository(db *sql.DB) *ServerRepository {
	return &ServerRepository{db: db}
}

// Create creates a new server record
func (r *ServerRepository) Create(server *models.RegisteredServer) error {
	query := `
		INSERT INTO registered_servers (
			hostname, os, kernel, arch, ip_addresses, ssh_version,
			ansible_user, ansible_pubkey, labels, ca_trusted
		)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	caTrusted := 0
	if server.CATrusted {
		caTrusted = 1
	}

	result, err := r.db.Exec(query,
		server.Hostname,
		server.OS,
		server.Kernel,
		server.Arch,
		server.IPAddresses,
		server.SSHVersion,
		server.AnsibleUser,
		server.AnsiblePubkey,
		server.Labels,
		caTrusted,
	)
	if err != nil {
		return fmt.Errorf("failed to create server: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get last insert id: %w", err)
	}

	server.ID = id
	server.RegisteredAt = time.Now()
	server.LastSeenAt = time.Now()

	return nil
}

// GetByHostname retrieves a server by hostname
func (r *ServerRepository) GetByHostname(hostname string) (*models.RegisteredServer, error) {
	query := `
		SELECT id, hostname, os, kernel, arch, ip_addresses, ssh_version,
		       ansible_user, ansible_pubkey, labels, ca_trusted, registered_at, last_seen_at
		FROM registered_servers
		WHERE hostname = ?
	`

	server := &models.RegisteredServer{}
	var caTrusted int

	err := r.db.QueryRow(query, hostname).Scan(
		&server.ID,
		&server.Hostname,
		&server.OS,
		&server.Kernel,
		&server.Arch,
		&server.IPAddresses,
		&server.SSHVersion,
		&server.AnsibleUser,
		&server.AnsiblePubkey,
		&server.Labels,
		&caTrusted,
		&server.RegisteredAt,
		&server.LastSeenAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("server not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get server: %w", err)
	}

	server.CATrusted = caTrusted == 1

	return server, nil
}

// UpdateOrCreate updates an existing server or creates a new one
func (r *ServerRepository) UpdateOrCreate(server *models.RegisteredServer) error {
	// Check if server exists
	existing, err := r.GetByHostname(server.Hostname)
	if err != nil && err.Error() != "server not found" {
		return err
	}

	if existing != nil {
		// Update existing
		return r.Update(existing.ID, server)
	}

	// Create new
	return r.Create(server)
}

// Update updates a server record
func (r *ServerRepository) Update(id int64, server *models.RegisteredServer) error {
	query := `
		UPDATE registered_servers
		SET os = ?, kernel = ?, arch = ?, ip_addresses = ?, ssh_version = ?,
		    ansible_user = ?, ansible_pubkey = ?, labels = ?, ca_trusted = ?,
		    last_seen_at = CURRENT_TIMESTAMP
		WHERE id = ?
	`

	caTrusted := 0
	if server.CATrusted {
		caTrusted = 1
	}

	_, err := r.db.Exec(query,
		server.OS,
		server.Kernel,
		server.Arch,
		server.IPAddresses,
		server.SSHVersion,
		server.AnsibleUser,
		server.AnsiblePubkey,
		server.Labels,
		caTrusted,
		id,
	)

	if err != nil {
		return fmt.Errorf("failed to update server: %w", err)
	}

	return nil
}

// List lists all registered servers
func (r *ServerRepository) List(limit int) ([]*models.RegisteredServer, error) {
	query := `
		SELECT id, hostname, os, kernel, arch, ip_addresses, ssh_version,
		       ansible_user, ansible_pubkey, labels, ca_trusted, registered_at, last_seen_at
		FROM registered_servers
		ORDER BY registered_at DESC
		LIMIT ?
	`

	rows, err := r.db.Query(query, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to list servers: %w", err)
	}
	defer rows.Close()

	var servers []*models.RegisteredServer

	for rows.Next() {
		server := &models.RegisteredServer{}
		var caTrusted int

		err := rows.Scan(
			&server.ID,
			&server.Hostname,
			&server.OS,
			&server.Kernel,
			&server.Arch,
			&server.IPAddresses,
			&server.SSHVersion,
			&server.AnsibleUser,
			&server.AnsiblePubkey,
			&server.Labels,
			&caTrusted,
			&server.RegisteredAt,
			&server.LastSeenAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan server: %w", err)
		}

		server.CATrusted = caTrusted == 1
		servers = append(servers, server)
	}

	return servers, nil
}

// Delete deletes a server
func (r *ServerRepository) Delete(id int64) error {
	query := `DELETE FROM registered_servers WHERE id = ?`

	_, err := r.db.Exec(query, id)
	if err != nil {
		return fmt.Errorf("failed to delete server: %w", err)
	}

	return nil
}
