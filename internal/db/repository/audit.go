package repository

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/adamscao/caserver/internal/models"
)

// AuditRepository handles audit log data access
type AuditRepository struct {
	db *sql.DB
}

// NewAuditRepository creates a new audit repository
func NewAuditRepository(db *sql.DB) *AuditRepository {
	return &AuditRepository{db: db}
}

// Create creates a new audit log entry
func (r *AuditRepository) Create(log *models.AuditLog) error {
	query := `
		INSERT INTO audit_logs (action, username, client_ip, user_agent, success, error_msg, details)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`

	success := 0
	if log.Success {
		success = 1
	}

	result, err := r.db.Exec(query,
		log.Action,
		log.Username,
		log.ClientIP,
		log.UserAgent,
		success,
		log.ErrorMsg,
		log.Details,
	)
	if err != nil {
		return fmt.Errorf("failed to create audit log: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get last insert id: %w", err)
	}

	log.ID = id
	log.Timestamp = time.Now()

	return nil
}

// List lists audit logs with optional filters
func (r *AuditRepository) List(username string, action string, limit int) ([]*models.AuditLog, error) {
	query := `
		SELECT id, timestamp, action, username, client_ip, user_agent, success, error_msg, details
		FROM audit_logs
		WHERE 1=1
	`
	args := []interface{}{}

	if username != "" {
		query += " AND username = ?"
		args = append(args, username)
	}

	if action != "" {
		query += " AND action = ?"
		args = append(args, action)
	}

	query += " ORDER BY timestamp DESC LIMIT ?"
	args = append(args, limit)

	rows, err := r.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list audit logs: %w", err)
	}
	defer rows.Close()

	var logs []*models.AuditLog

	for rows.Next() {
		log := &models.AuditLog{}
		var success int
		var username, userAgent, errorMsg, details sql.NullString

		err := rows.Scan(
			&log.ID,
			&log.Timestamp,
			&log.Action,
			&username,
			&log.ClientIP,
			&userAgent,
			&success,
			&errorMsg,
			&details,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan audit log: %w", err)
		}

		log.Success = success == 1
		if username.Valid {
			log.Username = username.String
		}
		if userAgent.Valid {
			log.UserAgent = userAgent.String
		}
		if errorMsg.Valid {
			log.ErrorMsg = errorMsg.String
		}
		if details.Valid {
			log.Details = details.String
		}

		logs = append(logs, log)
	}

	return logs, nil
}

// ListFailedAuth lists failed authentication attempts
func (r *AuditRepository) ListFailedAuth(since time.Time, limit int) ([]*models.AuditLog, error) {
	query := `
		SELECT id, timestamp, action, username, client_ip, user_agent, success, error_msg, details
		FROM audit_logs
		WHERE action = ? AND success = 0 AND timestamp >= ?
		ORDER BY timestamp DESC
		LIMIT ?
	`

	rows, err := r.db.Query(query, models.ActionAuthFailed, since, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to list failed auth: %w", err)
	}
	defer rows.Close()

	var logs []*models.AuditLog

	for rows.Next() {
		log := &models.AuditLog{}
		var success int
		var username, userAgent, errorMsg, details sql.NullString

		err := rows.Scan(
			&log.ID,
			&log.Timestamp,
			&log.Action,
			&username,
			&log.ClientIP,
			&userAgent,
			&success,
			&errorMsg,
			&details,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan audit log: %w", err)
		}

		log.Success = success == 1
		if username.Valid {
			log.Username = username.String
		}
		if userAgent.Valid {
			log.UserAgent = userAgent.String
		}
		if errorMsg.Valid {
			log.ErrorMsg = errorMsg.String
		}
		if details.Valid {
			log.Details = details.String
		}

		logs = append(logs, log)
	}

	return logs, nil
}

// CountByAction counts audit logs by action type
func (r *AuditRepository) CountByAction(action string, since time.Time) (int, error) {
	query := `
		SELECT COUNT(*)
		FROM audit_logs
		WHERE action = ? AND timestamp >= ?
	`

	var count int
	err := r.db.QueryRow(query, action, since).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count audit logs: %w", err)
	}

	return count, nil
}

// DeleteOld deletes audit logs older than the given date
func (r *AuditRepository) DeleteOld(before time.Time) (int64, error) {
	query := `
		DELETE FROM audit_logs
		WHERE timestamp < ?
	`

	result, err := r.db.Exec(query, before)
	if err != nil {
		return 0, fmt.Errorf("failed to delete old audit logs: %w", err)
	}

	count, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to get rows affected: %w", err)
	}

	return count, nil
}
