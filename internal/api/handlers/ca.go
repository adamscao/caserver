package handlers

import (
	"net/http"

	"github.com/adamscao/caserver/internal/ca"
	"github.com/gin-gonic/gin"
)

// CAHandler handles CA-related requests
type CAHandler struct {
	keyPair *ca.KeyPair
}

// NewCAHandler creates a new CA handler
func NewCAHandler(kp *ca.KeyPair) *CAHandler {
	return &CAHandler{
		keyPair: kp,
	}
}

// GetUserCAPublicKey returns the CA public key
// GET /v1/ca/user
func (h *CAHandler) GetUserCAPublicKey(c *gin.Context) {
	pubKey := h.keyPair.GetPublicKeyString()

	// Return as plain text
	c.Data(http.StatusOK, "text/plain; charset=utf-8", []byte(pubKey))
}
