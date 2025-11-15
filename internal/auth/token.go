package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
)

const (
	tokenLength = 32 // 32 bytes = 256 bits
)

// GenerateRenewToken generates a random renewal token
func GenerateRenewToken() (string, error) {
	bytes := make([]byte, tokenLength)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate token: %w", err)
	}

	// Encode to base64 for easier transmission
	token := base64.RawURLEncoding.EncodeToString(bytes)
	return token, nil
}

// HashToken hashes a token for storage
func HashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return base64.RawStdEncoding.EncodeToString(hash[:])
}

// VerifyToken verifies a token against its hash using constant-time comparison
func VerifyToken(token, storedHash string) bool {
	actualHash := HashToken(token)
	return subtle.ConstantTimeCompare([]byte(actualHash), []byte(storedHash)) == 1
}
