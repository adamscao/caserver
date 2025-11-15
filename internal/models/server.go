package models

import "time"

// RegisteredServer represents a registered server
type RegisteredServer struct {
	ID            int64     `json:"id"`
	Hostname      string    `json:"hostname"`
	OS            string    `json:"os,omitempty"`
	Kernel        string    `json:"kernel,omitempty"`
	Arch          string    `json:"arch,omitempty"`
	IPAddresses   string    `json:"ip_addresses,omitempty"`   // JSON array
	SSHVersion    string    `json:"ssh_version,omitempty"`
	AnsibleUser   string    `json:"ansible_user,omitempty"`
	AnsiblePubkey string    `json:"ansible_pubkey,omitempty"`
	Labels        string    `json:"labels,omitempty"`         // JSON array
	CATrusted     bool      `json:"ca_trusted"`
	RegisteredAt  time.Time `json:"registered_at"`
	LastSeenAt    time.Time `json:"last_seen_at"`
}
