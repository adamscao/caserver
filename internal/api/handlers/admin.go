package handlers

import (
	"log"
	"net/http"

	"github.com/adamscao/caserver/internal/auth"
	"github.com/adamscao/caserver/internal/db/repository"
	"github.com/adamscao/caserver/internal/models"
	"github.com/gin-gonic/gin"
)

// AdminHandler handles administrative operations
type AdminHandler struct {
	userRepo  *repository.UserRepository
	auditRepo *repository.AuditRepository
}

// NewAdminHandler creates a new admin handler
func NewAdminHandler(userRepo *repository.UserRepository, auditRepo *repository.AuditRepository) *AdminHandler {
	return &AdminHandler{
		userRepo:  userRepo,
		auditRepo: auditRepo,
	}
}

// CreateUserRequest represents a user creation request
type CreateUserRequest struct {
	Username       string `json:"username" binding:"required"`
	Password       string `json:"password" binding:"required"`
	TOTPSecret     string `json:"totp_secret" binding:"required"`
	Enabled        bool   `json:"enabled"`
	MaxCertsPerDay int    `json:"max_certs_per_day"`
}

// CreateUserResponse represents a user creation response
type CreateUserResponse struct {
	Status    string `json:"status"`
	UserID    int64  `json:"user_id"`
	TOTPQRUrl string `json:"totp_qr_url"`
}

// CreateUser creates a new user
// POST /v1/admin/users
func (h *AdminHandler) CreateUser(c *gin.Context) {
	var req CreateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		RespondError(c, http.StatusBadRequest, "invalid_request", "Invalid request body")
		return
	}

	clientIP := GetClientIP(c)
	userAgent := c.GetHeader("User-Agent")

	// Check if user already exists
	existingUser, _ := h.userRepo.GetByUsername(req.Username)
	if existingUser != nil {
		RespondError(c, http.StatusConflict, "user_exists", "User already exists")
		return
	}

	// Hash password
	passwordHash, err := auth.HashPassword(req.Password)
	if err != nil {
		log.Printf("Error hashing password: %v", err)
		RespondError(c, http.StatusInternalServerError, "internal_error", "Failed to hash password")
		return
	}

	// Set defaults
	enabled := req.Enabled
	maxCertsPerDay := req.MaxCertsPerDay
	if maxCertsPerDay <= 0 {
		maxCertsPerDay = 10
	}

	// Create user
	user := &models.User{
		Username:       req.Username,
		PasswordHash:   passwordHash,
		TOTPSecret:     req.TOTPSecret,
		Enabled:        enabled,
		MaxCertsPerDay: maxCertsPerDay,
	}

	if err := h.userRepo.Create(user); err != nil {
		log.Printf("Error creating user: %v", err)
		RespondError(c, http.StatusInternalServerError, "database_error", "Failed to create user")
		return
	}

	// Generate TOTP QR URL
	qrURL := auth.GenerateQRCodeURL(req.TOTPSecret, req.Username, "SSH-CA")

	// Log success
	h.auditRepo.Create(&models.AuditLog{
		Action:    models.ActionAdminCreateUser,
		Username:  req.Username,
		ClientIP:  clientIP,
		UserAgent: userAgent,
		Success:   true,
	})

	// Return response
	c.JSON(http.StatusOK, CreateUserResponse{
		Status:    "ok",
		UserID:    user.ID,
		TOTPQRUrl: qrURL,
	})
}
