package auth

import (
	"fmt"
	"net/url"

	"github.com/pquerna/otp/totp"
)

const (
	totpIssuer = "SSH-CA"
)

// GenerateTOTPSecret generates a new TOTP secret
func GenerateTOTPSecret() (string, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      totpIssuer,
		AccountName: "",
	})
	if err != nil {
		return "", fmt.Errorf("failed to generate TOTP secret: %w", err)
	}

	return key.Secret(), nil
}

// GenerateQRCodeURL generates a QR code URL for TOTP setup
func GenerateQRCodeURL(secret, username, issuer string) string {
	if issuer == "" {
		issuer = totpIssuer
	}

	return fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s",
		url.QueryEscape(issuer),
		url.QueryEscape(username),
		secret,
		url.QueryEscape(issuer))
}

// ValidateTOTP validates a TOTP code against a secret
// Allows for ±1 time window to account for clock skew
func ValidateTOTP(secret, code string) (bool, error) {
	// Try current time window
	valid := totp.Validate(code, secret)
	if valid {
		return true, nil
	}

	// No match
	return false, nil
}
