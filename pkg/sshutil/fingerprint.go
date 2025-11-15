package sshutil

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/ssh"
)

// GetFingerprint calculates the SHA256 fingerprint of an SSH public key
func GetFingerprint(pubkeyStr string) (string, error) {
	pubkey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pubkeyStr))
	if err != nil {
		return "", fmt.Errorf("failed to parse public key: %w", err)
	}

	hash := sha256.Sum256(pubkey.Marshal())
	b64hash := base64.RawStdEncoding.EncodeToString(hash[:])

	return fmt.Sprintf("SHA256:%s", b64hash), nil
}

// FingerprintMatches checks if two public keys have the same fingerprint
func FingerprintMatches(pubkey1, pubkey2 string) (bool, error) {
	fp1, err := GetFingerprint(pubkey1)
	if err != nil {
		return false, err
	}

	fp2, err := GetFingerprint(pubkey2)
	if err != nil {
		return false, err
	}

	return fp1 == fp2, nil
}
