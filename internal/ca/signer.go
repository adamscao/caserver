package ca

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"time"

	"golang.org/x/crypto/ssh"
)

// SignRequest represents a certificate signing request
type SignRequest struct {
	PublicKey      string
	Principal      string
	ValidityPeriod time.Duration
	SerialNumber   uint64
	KeyID          string
}

// SignCertificate signs an SSH certificate
func SignCertificate(kp *KeyPair, req *SignRequest) (string, error) {
	// Parse user's public key
	userPubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(req.PublicKey))
	if err != nil {
		return "", fmt.Errorf("failed to parse public key: %w", err)
	}

	// Calculate valid time range
	now := time.Now()
	validAfter := uint64(now.Unix())
	validBefore := uint64(now.Add(req.ValidityPeriod).Unix())

	// Create certificate with standard extensions
	cert := &ssh.Certificate{
		Key:             userPubKey,
		Serial:          req.SerialNumber,
		CertType:        ssh.UserCert,
		KeyId:           req.KeyID,
		ValidPrincipals: []string{req.Principal},
		ValidAfter:      validAfter,
		ValidBefore:     validBefore,
		// Add standard SSH certificate permissions/extensions
		Permissions: ssh.Permissions{
			Extensions: map[string]string{
				"permit-X11-forwarding":   "",
				"permit-agent-forwarding": "",
				"permit-port-forwarding":  "",
				"permit-pty":              "",
				"permit-user-rc":          "",
			},
		},
	}

	// Sign the certificate
	signer, err := ssh.NewSignerFromKey(kp.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("failed to create signer: %w", err)
	}

	if err := cert.SignCert(rand.Reader, signer); err != nil {
		return "", fmt.Errorf("failed to sign certificate: %w", err)
	}

	// Marshal certificate to string
	certBytes := ssh.MarshalAuthorizedKey(cert)
	// Remove trailing newline to ensure valid JSON
	certString := string(bytes.TrimSpace(certBytes))
	return certString, nil
}

// ParseCertificate parses an SSH certificate
func ParseCertificate(certData string) (*ssh.Certificate, error) {
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(certData))
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	cert, ok := pubKey.(*ssh.Certificate)
	if !ok {
		return nil, fmt.Errorf("not a certificate")
	}

	return cert, nil
}

// ValidateCertificate verifies that a certificate was signed by the CA
func ValidateCertificate(cert *ssh.Certificate, caPubKey ssh.PublicKey) error {
	// Create checker with CA public key
	checker := &ssh.CertChecker{
		IsUserAuthority: func(auth ssh.PublicKey) bool {
			return bytes.Equal(auth.Marshal(), caPubKey.Marshal())
		},
	}

	// Verify signature
	if err := checker.CheckCert(cert.ValidPrincipals[0], cert); err != nil {
		return fmt.Errorf("certificate validation failed: %w", err)
	}

	return nil
}
