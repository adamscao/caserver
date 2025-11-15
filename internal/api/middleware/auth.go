package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// AdminAuth middleware checks for admin token
func AdminAuth(adminToken string) gin.HandlerFunc {
	return func(c *gin.Context) {
		token := c.GetHeader("X-Admin-Token")

		if token == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "unauthorized",
				"message": "Admin token required",
			})
			c.Abort()
			return
		}

		if token != adminToken {
			c.JSON(http.StatusForbidden, gin.H{
				"error":   "forbidden",
				"message": "Invalid admin token",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}
