package repository

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/adamscao/caserver/internal/models"
)

// UserRepository handles user data access
type UserRepository struct {
	db *sql.DB
}

// NewUserRepository creates a new user repository
func NewUserRepository(db *sql.DB) *UserRepository {
	return &UserRepository{db: db}
}

// Create creates a new user
func (r *UserRepository) Create(user *models.User) error {
	query := `
		INSERT INTO users (username, password_hash, totp_secret, enabled, max_certs_per_day)
		VALUES (?, ?, ?, ?, ?)
	`

	result, err := r.db.Exec(query,
		user.Username,
		user.PasswordHash,
		user.TOTPSecret,
		user.Enabled,
		user.MaxCertsPerDay,
	)
	if err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get last insert id: %w", err)
	}

	user.ID = id
	user.CreatedAt = time.Now()
	user.UpdatedAt = time.Now()

	return nil
}

// GetByUsername retrieves a user by username
func (r *UserRepository) GetByUsername(username string) (*models.User, error) {
	query := `
		SELECT id, username, password_hash, totp_secret, enabled, max_certs_per_day, created_at, updated_at
		FROM users
		WHERE username = ?
	`

	user := &models.User{}
	var enabled int

	err := r.db.QueryRow(query, username).Scan(
		&user.ID,
		&user.Username,
		&user.PasswordHash,
		&user.TOTPSecret,
		&enabled,
		&user.MaxCertsPerDay,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("user not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	user.Enabled = enabled == 1

	return user, nil
}

// GetByID retrieves a user by ID
func (r *UserRepository) GetByID(id int64) (*models.User, error) {
	query := `
		SELECT id, username, password_hash, totp_secret, enabled, max_certs_per_day, created_at, updated_at
		FROM users
		WHERE id = ?
	`

	user := &models.User{}
	var enabled int

	err := r.db.QueryRow(query, id).Scan(
		&user.ID,
		&user.Username,
		&user.PasswordHash,
		&user.TOTPSecret,
		&enabled,
		&user.MaxCertsPerDay,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("user not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	user.Enabled = enabled == 1

	return user, nil
}

// Update updates a user
func (r *UserRepository) Update(user *models.User) error {
	query := `
		UPDATE users
		SET password_hash = ?, totp_secret = ?, enabled = ?, max_certs_per_day = ?, updated_at = CURRENT_TIMESTAMP
		WHERE id = ?
	`

	enabled := 0
	if user.Enabled {
		enabled = 1
	}

	_, err := r.db.Exec(query,
		user.PasswordHash,
		user.TOTPSecret,
		enabled,
		user.MaxCertsPerDay,
		user.ID,
	)

	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	return nil
}

// List lists all users
func (r *UserRepository) List() ([]*models.User, error) {
	query := `
		SELECT id, username, password_hash, totp_secret, enabled, max_certs_per_day, created_at, updated_at
		FROM users
		ORDER BY created_at DESC
	`

	rows, err := r.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}
	defer rows.Close()

	var users []*models.User

	for rows.Next() {
		user := &models.User{}
		var enabled int

		err := rows.Scan(
			&user.ID,
			&user.Username,
			&user.PasswordHash,
			&user.TOTPSecret,
			&enabled,
			&user.MaxCertsPerDay,
			&user.CreatedAt,
			&user.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan user: %w", err)
		}

		user.Enabled = enabled == 1
		users = append(users, user)
	}

	return users, nil
}

// Delete deletes a user
func (r *UserRepository) Delete(id int64) error {
	query := `DELETE FROM users WHERE id = ?`

	_, err := r.db.Exec(query, id)
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	return nil
}
