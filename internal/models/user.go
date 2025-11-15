package models

import "time"

// User represents a user account
type User struct {
	ID             int64     `json:"id"`
	Username       string    `json:"username"`
	PasswordHash   string    `json:"-"` // Never expose password hash in JSON
	TOTPSecret     string    `json:"-"` // Never expose TOTP secret in JSON
	Enabled        bool      `json:"enabled"`
	MaxCertsPerDay int       `json:"max_certs_per_day"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}
