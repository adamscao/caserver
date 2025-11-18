package handlers

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/adamscao/caserver/internal/auth"
	"github.com/adamscao/caserver/internal/ca"
	"github.com/adamscao/caserver/internal/config"
	"github.com/adamscao/caserver/internal/db/repository"
	"github.com/adamscao/caserver/internal/models"
	"github.com/adamscao/caserver/internal/policy"
	"github.com/adamscao/caserver/pkg/sshutil"
	"github.com/gin-gonic/gin"
)

// CertHandler handles certificate issuance and renewal
type CertHandler struct {
	config     *config.Config
	keyPair    *ca.KeyPair
	userRepo   *repository.UserRepository
	certRepo   *repository.CertRepository
	tokenRepo  *repository.TokenRepository
	auditRepo  *repository.AuditRepository
	validator  *policy.Validator
}

// NewCertHandler creates a new certificate handler
func NewCertHandler(
	cfg *config.Config,
	kp *ca.KeyPair,
	userRepo *repository.UserRepository,
	certRepo *repository.CertRepository,
	tokenRepo *repository.TokenRepository,
	auditRepo *repository.AuditRepository,
	validator *policy.Validator,
) *CertHandler {
	return &CertHandler{
		config:    cfg,
		keyPair:   kp,
		userRepo:  userRepo,
		certRepo:  certRepo,
		tokenRepo: tokenRepo,
		auditRepo: auditRepo,
		validator: validator,
	}
}

// IssueRequest represents a certificate issue request
type IssueRequest struct {
	Username           string   `json:"username" binding:"required"`
	Password           string   `json:"password" binding:"required"`
	TOTP               string   `json:"totp" binding:"required"`
	PublicKey          string   `json:"public_key" binding:"required"`
	ClientHostname     string   `json:"client_hostname"`
	RequestedPrincipals []string `json:"requested_principals" binding:"required"`
	RequestedValidity  string   `json:"requested_validity"`
}

// IssueResponse represents a certificate issue response
type IssueResponse struct {
	Certificate string    `json:"certificate"`
	ValidFrom   time.Time `json:"valid_from"`
	ValidTo     time.Time `json:"valid_to"`
	Principal   string    `json:"principal"`
	SerialNumber uint64   `json:"serial_number"`
	RenewToken  string    `json:"renew_token"`
}

// IssueCertificate handles certificate issuance
// POST /v1/certs/issue
func (h *CertHandler) IssueCertificate(c *gin.Context) {
	var req IssueRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		RespondError(c, http.StatusBadRequest, "invalid_request", "Invalid request body")
		return
	}

	clientIP := GetClientIP(c)
	userAgent := c.GetHeader("User-Agent")

	// Get user
	user, err := h.userRepo.GetByUsername(req.Username)
	if err != nil {
		h.logAuthFailure(req.Username, clientIP, userAgent, "User not found")
		RespondError(c, http.StatusUnauthorized, "invalid_credentials", "Invalid username or password")
		return
	}

	// Verify password
	validPassword, err := auth.VerifyPassword(req.Password, user.PasswordHash)
	if err != nil || !validPassword {
		h.logAuthFailure(req.Username, clientIP, userAgent, "Invalid password")
		RespondError(c, http.StatusUnauthorized, "invalid_credentials", "Invalid username or password")
		return
	}

	// Verify TOTP
	validTOTP, err := auth.ValidateTOTP(user.TOTPSecret, req.TOTP)
	if err != nil || !validTOTP {
		h.logAuthFailure(req.Username, clientIP, userAgent, "Invalid TOTP")
		RespondError(c, http.StatusUnauthorized, "invalid_totp", "Invalid TOTP code")
		return
	}

	// Parse requested validity
	var requestedValidity time.Duration
	if req.RequestedValidity != "" {
		requestedValidity, err = time.ParseDuration(req.RequestedValidity)
		if err != nil {
			RespondError(c, http.StatusBadRequest, "invalid_validity", "Invalid validity format")
			return
		}
	}

	// Validate principal (should only request one, which matches username)
	if len(req.RequestedPrincipals) != 1 {
		RespondError(c, http.StatusBadRequest, "invalid_principal", "Must request exactly one principal")
		return
	}
	principal := req.RequestedPrincipals[0]

	// Validate against policy
	validity, err := h.validator.ValidateIssueRequest(user, principal, requestedValidity)
	if err != nil {
		RespondError(c, http.StatusForbidden, "policy_violation", err.Error())
		return
	}

	// Get public key fingerprint
	fingerprint, err := sshutil.GetFingerprint(req.PublicKey)
	if err != nil {
		RespondError(c, http.StatusBadRequest, "invalid_public_key", "Invalid public key format")
		return
	}

	// Get next serial number
	serialNumber, err := h.certRepo.GetNextSerialNumber()
	if err != nil {
		log.Printf("Error getting serial number: %v", err)
		RespondError(c, http.StatusInternalServerError, "internal_error", "Failed to generate serial number")
		return
	}

	// Sign certificate
	keyID := fmt.Sprintf("%s@%s", req.Username, req.ClientHostname)
	certString, err := ca.SignCertificate(h.keyPair, &ca.SignRequest{
		PublicKey:      req.PublicKey,
		Principal:      principal,
		ValidityPeriod: validity,
		SerialNumber:   serialNumber,
		KeyID:          keyID,
	})
	if err != nil {
		log.Printf("Error signing certificate: %v", err)
		RespondError(c, http.StatusInternalServerError, "signing_error", "Failed to sign certificate")
		return
	}

	// Calculate validity times
	now := time.Now()
	validFrom := now
	validTo := now.Add(validity)

	// Save certificate record
	certRecord := &models.CertificateRecord{
		UserID:         user.ID,
		PublicKeyFP:    fingerprint,
		SerialNumber:   serialNumber,
		Principal:      principal,
		ValidFrom:      validFrom,
		ValidTo:        validTo,
		ClientIP:       clientIP,
		ClientHostname: req.ClientHostname,
		UserAgent:      userAgent,
	}
	if err := h.certRepo.Create(certRecord); err != nil {
		log.Printf("Error saving certificate record: %v", err)
		// Continue anyway - certificate is already signed
	}

	// Generate renew token
	renewToken, err := auth.GenerateRenewToken()
	if err != nil {
		log.Printf("Error generating renew token: %v", err)
		// Continue without token
		renewToken = ""
	}

	// Save renew token
	if renewToken != "" {
		tokenHash := auth.HashToken(renewToken)
		tokenExpiry := time.Now().Add(h.config.GetRenewTokenValidityDuration())
		renewTokenRecord := &models.RenewToken{
			UserID:      user.ID,
			TokenHash:   tokenHash,
			PublicKeyFP: fingerprint,
			ExpiresAt:   tokenExpiry,
		}
		if err := h.tokenRepo.Create(renewTokenRecord); err != nil {
			log.Printf("Error saving renew token: %v", err)
			// Continue without token
			renewToken = ""
		}
	}

	// Log success
	h.logSuccess(models.ActionCertIssue, req.Username, clientIP, userAgent, map[string]interface{}{
		"public_key_fp": fingerprint,
		"principal":     principal,
		"validity":      validity.String(),
		"serial":        serialNumber,
	})

	// Return response
	c.JSON(http.StatusOK, IssueResponse{
		Certificate:  certString,
		ValidFrom:    validFrom,
		ValidTo:      validTo,
		Principal:    principal,
		SerialNumber: serialNumber,
		RenewToken:   renewToken,
	})
}

// RenewRequest represents a certificate renewal request
type RenewRequest struct {
	Username          string `json:"username"` // Optional - will be derived from token if not provided
	PublicKey         string `json:"public_key" binding:"required"`
	RenewToken        string `json:"renew_token" binding:"required"`
	CurrentCert       string `json:"current_cert"`
	RequestedValidity string `json:"requested_validity"`
}

// RenewResponse represents a certificate renewal response
type RenewResponse struct {
	Certificate  string    `json:"certificate"`
	ValidFrom    time.Time `json:"valid_from"`
	ValidTo      time.Time `json:"valid_to"`
	Principal    string    `json:"principal"`
	SerialNumber uint64    `json:"serial_number"`
}

// RenewCertificate handles certificate renewal
// POST /v1/certs/renew
func (h *CertHandler) RenewCertificate(c *gin.Context) {
	var req RenewRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		RespondError(c, http.StatusBadRequest, "invalid_request", "Invalid request body")
		return
	}

	clientIP := GetClientIP(c)
	userAgent := c.GetHeader("User-Agent")

	// Get public key fingerprint
	fingerprint, err := sshutil.GetFingerprint(req.PublicKey)
	if err != nil {
		RespondError(c, http.StatusBadRequest, "invalid_public_key", "Invalid public key format")
		return
	}

	// Validate token (this also checks public key binding)
	tokenHash := auth.HashToken(req.RenewToken)
	token, err := h.tokenRepo.ValidateToken(tokenHash, fingerprint)
	if err != nil {
		RespondError(c, http.StatusUnauthorized, "invalid_token", "Invalid or expired renew token")
		return
	}

	// Get user from token (token.UserID is already validated)
	user, err := h.userRepo.GetByID(token.UserID)
	if err != nil {
		RespondError(c, http.StatusUnauthorized, "invalid_user", "User not found")
		return
	}

	// Validate against policy
	validity, err := h.validator.ValidateRenewRequest(user, token)
	if err != nil {
		RespondError(c, http.StatusForbidden, "policy_violation", err.Error())
		return
	}

	// Get next serial number
	serialNumber, err := h.certRepo.GetNextSerialNumber()
	if err != nil {
		log.Printf("Error getting serial number: %v", err)
		RespondError(c, http.StatusInternalServerError, "internal_error", "Failed to generate serial number")
		return
	}

	// Sign certificate
	principal := user.Username
	keyID := fmt.Sprintf("%s-renew-%d", user.Username, time.Now().Unix())
	certString, err := ca.SignCertificate(h.keyPair, &ca.SignRequest{
		PublicKey:      req.PublicKey,
		Principal:      principal,
		ValidityPeriod: validity,
		SerialNumber:   serialNumber,
		KeyID:          keyID,
	})
	if err != nil {
		log.Printf("Error signing certificate: %v", err)
		RespondError(c, http.StatusInternalServerError, "signing_error", "Failed to sign certificate")
		return
	}

	// Calculate validity times
	now := time.Now()
	validFrom := now
	validTo := now.Add(validity)

	// Save certificate record
	certRecord := &models.CertificateRecord{
		UserID:       user.ID,
		PublicKeyFP:  fingerprint,
		SerialNumber: serialNumber,
		Principal:    principal,
		ValidFrom:    validFrom,
		ValidTo:      validTo,
		ClientIP:     clientIP,
		UserAgent:    userAgent,
	}
	if err := h.certRepo.Create(certRecord); err != nil {
		log.Printf("Error saving certificate record: %v", err)
		// Continue anyway
	}

	// Update token last used
	if err := h.tokenRepo.UpdateLastUsed(token.ID); err != nil {
		log.Printf("Error updating token last used: %v", err)
	}

	// Log success
	h.logSuccess(models.ActionCertRenew, req.Username, clientIP, userAgent, map[string]interface{}{
		"public_key_fp": fingerprint,
		"principal":     principal,
		"validity":      validity.String(),
		"serial":        serialNumber,
	})

	// Return response
	c.JSON(http.StatusOK, RenewResponse{
		Certificate:  certString,
		ValidFrom:    validFrom,
		ValidTo:      validTo,
		Principal:    principal,
		SerialNumber: serialNumber,
	})
}

// Helper methods for audit logging
func (h *CertHandler) logAuthFailure(username, clientIP, userAgent, reason string) {
	h.auditRepo.Create(&models.AuditLog{
		Action:    models.ActionAuthFailed,
		Username:  username,
		ClientIP:  clientIP,
		UserAgent: userAgent,
		Success:   false,
		ErrorMsg:  reason,
	})
}

func (h *CertHandler) logSuccess(action, username, clientIP, userAgent string, details interface{}) {
	detailsJSON := ""
	// In production, properly marshal to JSON
	h.auditRepo.Create(&models.AuditLog{
		Action:    action,
		Username:  username,
		ClientIP:  clientIP,
		UserAgent: userAgent,
		Success:   true,
		Details:   detailsJSON,
	})
}
