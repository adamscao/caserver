package models

import "time"

// CertificateRecord represents a certificate issuance record
type CertificateRecord struct {
	ID             int64     `json:"id"`
	UserID         int64     `json:"user_id"`
	PublicKeyFP    string    `json:"public_key_fp"`
	SerialNumber   uint64    `json:"serial_number"`
	Principal      string    `json:"principal"`
	ValidFrom      time.Time `json:"valid_from"`
	ValidTo        time.Time `json:"valid_to"`
	ClientIP       string    `json:"client_ip"`
	ClientHostname string    `json:"client_hostname,omitempty"`
	UserAgent      string    `json:"user_agent,omitempty"`
	IssuedAt       time.Time `json:"issued_at"`
}
