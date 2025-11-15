package policy

import (
	"fmt"
	"time"

	"github.com/adamscao/caserver/internal/config"
	"github.com/adamscao/caserver/internal/db/repository"
	"github.com/adamscao/caserver/internal/models"
)

// Validator validates certificate signing requests against policy
type Validator struct {
	config   *config.Config
	certRepo *repository.CertRepository
}

// NewValidator creates a new policy validator
func NewValidator(cfg *config.Config, certRepo *repository.CertRepository) *Validator {
	return &Validator{
		config:   cfg,
		certRepo: certRepo,
	}
}

// ValidateIssueRequest validates a certificate issue request
func (v *Validator) ValidateIssueRequest(user *models.User, principal string, requestedValidity time.Duration) (time.Duration, error) {
	// Check if user is enabled
	if !user.Enabled {
		return 0, fmt.Errorf("user account is disabled")
	}

	// Validate principal matches username
	if principal != user.Username {
		return 0, fmt.Errorf("principal must match username (got %s, expected %s)", principal, user.Username)
	}

	// Check daily certificate limit
	count, err := v.certRepo.GetUserCertCountToday(user.ID)
	if err != nil {
		return 0, fmt.Errorf("failed to check daily limit: %w", err)
	}

	maxCerts := user.MaxCertsPerDay
	if maxCerts <= 0 {
		maxCerts = v.config.Policy.MaxCertsPerDay
	}

	if count >= maxCerts {
		return 0, fmt.Errorf("daily certificate limit exceeded (%d/%d)", count, maxCerts)
	}

	// Validate and adjust validity period
	adjustedValidity := v.adjustValidity(requestedValidity)

	return adjustedValidity, nil
}

// ValidateRenewRequest validates a certificate renewal request
func (v *Validator) ValidateRenewRequest(user *models.User, token *models.RenewToken) (time.Duration, error) {
	// Check if user is enabled
	if !user.Enabled {
		return 0, fmt.Errorf("user account is disabled")
	}

	// Check if token belongs to user
	if token.UserID != user.ID {
		return 0, fmt.Errorf("token does not belong to user")
	}

	// Check if token is expired
	if time.Now().After(token.ExpiresAt) {
		return 0, fmt.Errorf("token has expired")
	}

	// Check daily certificate limit (renewal also counts)
	count, err := v.certRepo.GetUserCertCountToday(user.ID)
	if err != nil {
		return 0, fmt.Errorf("failed to check daily limit: %w", err)
	}

	maxCerts := user.MaxCertsPerDay
	if maxCerts <= 0 {
		maxCerts = v.config.Policy.MaxCertsPerDay
	}

	if count >= maxCerts {
		return 0, fmt.Errorf("daily certificate limit exceeded (%d/%d)", count, maxCerts)
	}

	// Use default validity for renewals
	validity := v.config.GetDefaultValidityDuration()

	return validity, nil
}

// adjustValidity adjusts the requested validity to comply with policy
func (v *Validator) adjustValidity(requested time.Duration) time.Duration {
	maxValidity := v.config.GetMaxValidityDuration()

	// If requested is zero or negative, use default
	if requested <= 0 {
		return v.config.GetDefaultValidityDuration()
	}

	// If requested exceeds max, cap at max
	if requested > maxValidity {
		return maxValidity
	}

	return requested
}

// GetMaxValidity returns the maximum allowed validity period
func (v *Validator) GetMaxValidity() time.Duration {
	return v.config.GetMaxValidityDuration()
}

// GetDefaultValidity returns the default validity period
func (v *Validator) GetDefaultValidity() time.Duration {
	return v.config.GetDefaultValidityDuration()
}
