package repository

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/adamscao/caserver/internal/models"
)

// TokenRepository handles renew token data access
type TokenRepository struct {
	db *sql.DB
}

// NewTokenRepository creates a new token repository
func NewTokenRepository(db *sql.DB) *TokenRepository {
	return &TokenRepository{db: db}
}

// Create creates a new renew token
func (r *TokenRepository) Create(token *models.RenewToken) error {
	query := `
		INSERT INTO renew_tokens (user_id, token_hash, public_key_fp, expires_at)
		VALUES (?, ?, ?, ?)
	`

	result, err := r.db.Exec(query,
		token.UserID,
		token.TokenHash,
		token.PublicKeyFP,
		token.ExpiresAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create renew token: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get last insert id: %w", err)
	}

	token.ID = id
	token.CreatedAt = time.Now()

	return nil
}

// GetByTokenHash retrieves a token by its hash
func (r *TokenRepository) GetByTokenHash(tokenHash string) (*models.RenewToken, error) {
	query := `
		SELECT id, user_id, token_hash, public_key_fp, created_at, expires_at, last_used_at
		FROM renew_tokens
		WHERE token_hash = ?
	`

	token := &models.RenewToken{}
	var lastUsedAt sql.NullTime

	err := r.db.QueryRow(query, tokenHash).Scan(
		&token.ID,
		&token.UserID,
		&token.TokenHash,
		&token.PublicKeyFP,
		&token.CreatedAt,
		&token.ExpiresAt,
		&lastUsedAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("token not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get token: %w", err)
	}

	if lastUsedAt.Valid {
		token.LastUsedAt = &lastUsedAt.Time
	}

	return token, nil
}

// ValidateToken validates a token (checks existence and expiry)
func (r *TokenRepository) ValidateToken(tokenHash, publicKeyFP string) (*models.RenewToken, error) {
	query := `
		SELECT id, user_id, token_hash, public_key_fp, created_at, expires_at, last_used_at
		FROM renew_tokens
		WHERE token_hash = ? AND public_key_fp = ? AND expires_at > DATETIME('now')
	`

	token := &models.RenewToken{}
	var lastUsedAt sql.NullTime

	err := r.db.QueryRow(query, tokenHash, publicKeyFP).Scan(
		&token.ID,
		&token.UserID,
		&token.TokenHash,
		&token.PublicKeyFP,
		&token.CreatedAt,
		&token.ExpiresAt,
		&lastUsedAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("token not found or expired")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to validate token: %w", err)
	}

	if lastUsedAt.Valid {
		token.LastUsedAt = &lastUsedAt.Time
	}

	return token, nil
}

// UpdateLastUsed updates the last_used_at timestamp
func (r *TokenRepository) UpdateLastUsed(id int64) error {
	query := `
		UPDATE renew_tokens
		SET last_used_at = CURRENT_TIMESTAMP
		WHERE id = ?
	`

	_, err := r.db.Exec(query, id)
	if err != nil {
		return fmt.Errorf("failed to update last used: %w", err)
	}

	return nil
}

// ListByUserID lists all tokens for a user
func (r *TokenRepository) ListByUserID(userID int64) ([]*models.RenewToken, error) {
	query := `
		SELECT id, user_id, token_hash, public_key_fp, created_at, expires_at, last_used_at
		FROM renew_tokens
		WHERE user_id = ?
		ORDER BY created_at DESC
	`

	rows, err := r.db.Query(query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to list tokens: %w", err)
	}
	defer rows.Close()

	var tokens []*models.RenewToken

	for rows.Next() {
		token := &models.RenewToken{}
		var lastUsedAt sql.NullTime

		err := rows.Scan(
			&token.ID,
			&token.UserID,
			&token.TokenHash,
			&token.PublicKeyFP,
			&token.CreatedAt,
			&token.ExpiresAt,
			&lastUsedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan token: %w", err)
		}

		if lastUsedAt.Valid {
			token.LastUsedAt = &lastUsedAt.Time
		}

		tokens = append(tokens, token)
	}

	return tokens, nil
}

// DeleteExpired deletes all expired tokens
func (r *TokenRepository) DeleteExpired() (int64, error) {
	query := `
		DELETE FROM renew_tokens
		WHERE expires_at < DATETIME('now', '-30 days')
	`

	result, err := r.db.Exec(query)
	if err != nil {
		return 0, fmt.Errorf("failed to delete expired tokens: %w", err)
	}

	count, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to get rows affected: %w", err)
	}

	return count, nil
}

// Delete deletes a token by ID
func (r *TokenRepository) Delete(id int64) error {
	query := `DELETE FROM renew_tokens WHERE id = ?`

	_, err := r.db.Exec(query, id)
	if err != nil {
		return fmt.Errorf("failed to delete token: %w", err)
	}

	return nil
}
