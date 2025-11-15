package api

import (
	"github.com/adamscao/caserver/internal/api/handlers"
	"github.com/adamscao/caserver/internal/api/middleware"
	"github.com/adamscao/caserver/internal/ca"
	"github.com/adamscao/caserver/internal/config"
	"github.com/adamscao/caserver/internal/db/repository"
	"github.com/adamscao/caserver/internal/policy"
	"github.com/gin-gonic/gin"
)

// Server represents the HTTP server
type Server struct {
	router *gin.Engine
	config *config.Config
}

// NewServer creates a new API server
func NewServer(
	cfg *config.Config,
	keyPair *ca.KeyPair,
	userRepo *repository.UserRepository,
	certRepo *repository.CertRepository,
	tokenRepo *repository.TokenRepository,
	serverRepo *repository.ServerRepository,
	auditRepo *repository.AuditRepository,
	validator *policy.Validator,
) *Server {
	// Set Gin mode
	if cfg.Logging.Level == "debug" {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.New()

	// Global middleware
	router.Use(gin.Recovery())
	router.Use(middleware.Logger())

	// Create handlers
	caHandler := handlers.NewCAHandler(keyPair)
	certHandler := handlers.NewCertHandler(cfg, keyPair, userRepo, certRepo, tokenRepo, auditRepo, validator)
	adminHandler := handlers.NewAdminHandler(userRepo, auditRepo)
	registerHandler := handlers.NewRegisterHandler(serverRepo, auditRepo)
	bootstrapHandler := handlers.NewBootstrapHandler()

	// API v1 routes
	v1 := router.Group("/v1")
	{
		// Public endpoints
		ca := v1.Group("/ca")
		{
			ca.GET("/user", caHandler.GetUserCAPublicKey)
		}

		// Bootstrap endpoints
		bootstrap := v1.Group("/bootstrap")
		{
			bootstrap.GET("/server.sh", bootstrapHandler.GetServerScript)
			bootstrap.GET("/client.sh", bootstrapHandler.GetClientScript)
		}

		// Server registration
		register := v1.Group("/register")
		{
			register.POST("/server", registerHandler.RegisterServer)
		}

		// Certificate endpoints
		certs := v1.Group("/certs")
		{
			certs.POST("/issue", certHandler.IssueCertificate)
			certs.POST("/renew", certHandler.RenewCertificate)
		}

		// Admin endpoints (require admin token)
		admin := v1.Group("/admin")
		admin.Use(middleware.AdminAuth(cfg.Admin.Token))
		{
			admin.POST("/users", adminHandler.CreateUser)
		}
	}

	// Health check
	router.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status": "ok",
		})
	})

	return &Server{
		router: router,
		config: cfg,
	}
}

// Run starts the HTTP server
func (s *Server) Run() error {
	return s.router.Run(s.config.Server.ListenAddr)
}

// Router returns the underlying Gin router
func (s *Server) Router() *gin.Engine {
	return s.router
}
