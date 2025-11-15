package handlers

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/adamscao/caserver/internal/db/repository"
	"github.com/adamscao/caserver/internal/models"
	"github.com/gin-gonic/gin"
)

// RegisterHandler handles server registration
type RegisterHandler struct {
	serverRepo *repository.ServerRepository
	auditRepo  *repository.AuditRepository
}

// NewRegisterHandler creates a new register handler
func NewRegisterHandler(serverRepo *repository.ServerRepository, auditRepo *repository.AuditRepository) *RegisterHandler {
	return &RegisterHandler{
		serverRepo: serverRepo,
		auditRepo:  auditRepo,
	}
}

// RegisterServerRequest represents a server registration request
type RegisterServerRequest struct {
	Hostname      string   `json:"hostname" binding:"required"`
	OS            string   `json:"os"`
	Kernel        string   `json:"kernel"`
	Arch          string   `json:"arch"`
	IPAddresses   []string `json:"ip_addresses"`
	SSHVersion    string   `json:"ssh_version"`
	AnsibleUser   string   `json:"ansible_user"`
	AnsiblePubkey string   `json:"ansible_pubkey"`
	Labels        []string `json:"labels"`
	CATrusted     bool     `json:"ca_trusted"`
}

// RegisterServerResponse represents a server registration response
type RegisterServerResponse struct {
	Status      string   `json:"status"`
	ServerID    string   `json:"server_id"`
	NextActions []string `json:"next_actions"`
}

// RegisterServer handles server registration
// POST /v1/register/server
func (h *RegisterHandler) RegisterServer(c *gin.Context) {
	var req RegisterServerRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		RespondError(c, http.StatusBadRequest, "invalid_request", "Invalid request body")
		return
	}

	clientIP := GetClientIP(c)
	userAgent := c.GetHeader("User-Agent")

	// Marshal IP addresses and labels to JSON
	ipAddressesJSON, _ := json.Marshal(req.IPAddresses)
	labelsJSON, _ := json.Marshal(req.Labels)

	// Create server record
	server := &models.RegisteredServer{
		Hostname:      req.Hostname,
		OS:            req.OS,
		Kernel:        req.Kernel,
		Arch:          req.Arch,
		IPAddresses:   string(ipAddressesJSON),
		SSHVersion:    req.SSHVersion,
		AnsibleUser:   req.AnsibleUser,
		AnsiblePubkey: req.AnsiblePubkey,
		Labels:        string(labelsJSON),
		CATrusted:     req.CATrusted,
	}

	// Update or create
	if err := h.serverRepo.UpdateOrCreate(server); err != nil {
		log.Printf("Error registering server: %v", err)
		RespondError(c, http.StatusInternalServerError, "database_error", "Failed to register server")
		return
	}

	// Log success
	h.auditRepo.Create(&models.AuditLog{
		Action:    models.ActionServerRegister,
		Username:  req.Hostname,
		ClientIP:  clientIP,
		UserAgent: userAgent,
		Success:   true,
	})

	// Return response
	c.JSON(http.StatusOK, RegisterServerResponse{
		Status:      "ok",
		ServerID:    string(rune(server.ID)),
		NextActions: []string{},
	})
}
