package models

import "time"

// AuditLog represents an audit log entry
type AuditLog struct {
	ID        int64     `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Action    string    `json:"action"`
	Username  string    `json:"username,omitempty"`
	ClientIP  string    `json:"client_ip"`
	UserAgent string    `json:"user_agent,omitempty"`
	Success   bool      `json:"success"`
	ErrorMsg  string    `json:"error_msg,omitempty"`
	Details   string    `json:"details,omitempty"` // JSON
}

// Audit action constants
const (
	ActionCertIssue      = "cert_issue"
	ActionCertRenew      = "cert_renew"
	ActionAdminCreateUser = "admin_create_user"
	ActionServerRegister = "server_register"
	ActionAuthFailed     = "auth_failed"
)
