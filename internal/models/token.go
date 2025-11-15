package models

import "time"

// RenewToken represents a certificate renewal token
type RenewToken struct {
	ID           int64      `json:"id"`
	UserID       int64      `json:"user_id"`
	TokenHash    string     `json:"-"` // Never expose token hash
	PublicKeyFP  string     `json:"public_key_fp"`
	CreatedAt    time.Time  `json:"created_at"`
	ExpiresAt    time.Time  `json:"expires_at"`
	LastUsedAt   *time.Time `json:"last_used_at,omitempty"`
}
