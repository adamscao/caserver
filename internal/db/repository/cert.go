package repository

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/adamscao/caserver/internal/models"
)

// CertRepository handles certificate record data access
type CertRepository struct {
	db *sql.DB
}

// NewCertRepository creates a new certificate repository
func NewCertRepository(db *sql.DB) *CertRepository {
	return &CertRepository{db: db}
}

// Create creates a new certificate record
func (r *CertRepository) Create(cert *models.CertificateRecord) error {
	query := `
		INSERT INTO certificates (
			user_id, public_key_fp, serial_number, principal,
			valid_from, valid_to, client_ip, client_hostname, user_agent
		)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	result, err := r.db.Exec(query,
		cert.UserID,
		cert.PublicKeyFP,
		cert.SerialNumber,
		cert.Principal,
		cert.ValidFrom,
		cert.ValidTo,
		cert.ClientIP,
		cert.ClientHostname,
		cert.UserAgent,
	)
	if err != nil {
		return fmt.Errorf("failed to create certificate record: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get last insert id: %w", err)
	}

	cert.ID = id
	cert.IssuedAt = time.Now()

	return nil
}

// GetBySerialNumber retrieves a certificate by serial number
func (r *CertRepository) GetBySerialNumber(serial uint64) (*models.CertificateRecord, error) {
	query := `
		SELECT id, user_id, public_key_fp, serial_number, principal,
		       valid_from, valid_to, client_ip, client_hostname, user_agent, issued_at
		FROM certificates
		WHERE serial_number = ?
	`

	cert := &models.CertificateRecord{}

	err := r.db.QueryRow(query, serial).Scan(
		&cert.ID,
		&cert.UserID,
		&cert.PublicKeyFP,
		&cert.SerialNumber,
		&cert.Principal,
		&cert.ValidFrom,
		&cert.ValidTo,
		&cert.ClientIP,
		&cert.ClientHostname,
		&cert.UserAgent,
		&cert.IssuedAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("certificate not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get certificate: %w", err)
	}

	return cert, nil
}

// GetUserCertCountToday returns the number of certificates issued to a user today
func (r *CertRepository) GetUserCertCountToday(userID int64) (int, error) {
	query := `
		SELECT COUNT(*)
		FROM certificates
		WHERE user_id = ? AND DATE(issued_at) = DATE('now')
	`

	var count int
	err := r.db.QueryRow(query, userID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to get cert count: %w", err)
	}

	return count, nil
}

// GetNextSerialNumber returns the next available serial number
func (r *CertRepository) GetNextSerialNumber() (uint64, error) {
	query := `
		SELECT COALESCE(MAX(serial_number), 0) + 1
		FROM certificates
	`

	var serial uint64
	err := r.db.QueryRow(query).Scan(&serial)
	if err != nil {
		return 0, fmt.Errorf("failed to get next serial number: %w", err)
	}

	return serial, nil
}

// ListByUserID lists all certificates for a user
func (r *CertRepository) ListByUserID(userID int64, limit int) ([]*models.CertificateRecord, error) {
	query := `
		SELECT id, user_id, public_key_fp, serial_number, principal,
		       valid_from, valid_to, client_ip, client_hostname, user_agent, issued_at
		FROM certificates
		WHERE user_id = ?
		ORDER BY issued_at DESC
		LIMIT ?
	`

	rows, err := r.db.Query(query, userID, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to list certificates: %w", err)
	}
	defer rows.Close()

	var certs []*models.CertificateRecord

	for rows.Next() {
		cert := &models.CertificateRecord{}
		err := rows.Scan(
			&cert.ID,
			&cert.UserID,
			&cert.PublicKeyFP,
			&cert.SerialNumber,
			&cert.Principal,
			&cert.ValidFrom,
			&cert.ValidTo,
			&cert.ClientIP,
			&cert.ClientHostname,
			&cert.UserAgent,
			&cert.IssuedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan certificate: %w", err)
		}

		certs = append(certs, cert)
	}

	return certs, nil
}

// ListExpiringSoon lists certificates expiring within the given duration
func (r *CertRepository) ListExpiringSoon(within time.Duration) ([]*models.CertificateRecord, error) {
	query := `
		SELECT id, user_id, public_key_fp, serial_number, principal,
		       valid_from, valid_to, client_ip, client_hostname, user_agent, issued_at
		FROM certificates
		WHERE valid_to < ? AND valid_to > DATETIME('now')
		ORDER BY valid_to ASC
	`

	expiryTime := time.Now().Add(within)

	rows, err := r.db.Query(query, expiryTime)
	if err != nil {
		return nil, fmt.Errorf("failed to list expiring certificates: %w", err)
	}
	defer rows.Close()

	var certs []*models.CertificateRecord

	for rows.Next() {
		cert := &models.CertificateRecord{}
		err := rows.Scan(
			&cert.ID,
			&cert.UserID,
			&cert.PublicKeyFP,
			&cert.SerialNumber,
			&cert.Principal,
			&cert.ValidFrom,
			&cert.ValidTo,
			&cert.ClientIP,
			&cert.ClientHostname,
			&cert.UserAgent,
			&cert.IssuedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan certificate: %w", err)
		}

		certs = append(certs, cert)
	}

	return certs, nil
}
