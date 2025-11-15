package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// ErrorResponse represents an error response
type ErrorResponse struct {
	Error   string      `json:"error"`
	Message string      `json:"message"`
	Details interface{} `json:"details,omitempty"`
}

// RespondError sends an error response
func RespondError(c *gin.Context, statusCode int, errorCode string, message string) {
	c.JSON(statusCode, ErrorResponse{
		Error:   errorCode,
		Message: message,
	})
}

// RespondErrorWithDetails sends an error response with details
func RespondErrorWithDetails(c *gin.Context, statusCode int, errorCode string, message string, details interface{}) {
	c.JSON(statusCode, ErrorResponse{
		Error:   errorCode,
		Message: message,
		Details: details,
	})
}

// RespondSuccess sends a success response
func RespondSuccess(c *gin.Context, data interface{}) {
	c.JSON(http.StatusOK, data)
}

// GetClientIP gets the real client IP address
func GetClientIP(c *gin.Context) string {
	// Try X-Forwarded-For header first (for proxied requests)
	if ip := c.GetHeader("X-Forwarded-For"); ip != "" {
		return ip
	}

	// Try X-Real-IP header
	if ip := c.GetHeader("X-Real-IP"); ip != "" {
		return ip
	}

	// Fall back to RemoteAddr
	return c.ClientIP()
}
