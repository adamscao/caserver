package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/adamscao/caserver/internal/api"
	"github.com/adamscao/caserver/internal/ca"
	"github.com/adamscao/caserver/internal/config"
	"github.com/adamscao/caserver/internal/db"
	"github.com/adamscao/caserver/internal/db/repository"
	"github.com/adamscao/caserver/internal/policy"
)

var (
	// Version information (set via ldflags)
	Version   = "dev"
	Commit    = "unknown"
	BuildTime = "unknown"
)

func main() {
	// Parse command line flags
	configPath := flag.String("config", "/etc/ssh-ca/config.yaml", "Path to configuration file")
	showVersion := flag.Bool("version", false, "Show version information")
	flag.Parse()

	if *showVersion {
		fmt.Printf("SSH CA Server\n")
		fmt.Printf("Version:    %s\n", Version)
		fmt.Printf("Commit:     %s\n", Commit)
		fmt.Printf("Build Time: %s\n", BuildTime)
		os.Exit(0)
	}

	log.Printf("Starting SSH CA Server %s (commit: %s)", Version, Commit)

	// Load configuration
	log.Printf("Loading configuration from %s", *configPath)
	cfg, err := config.LoadWithEnv(*configPath)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize database
	log.Printf("Connecting to database: %s", cfg.Database.Path)
	database, err := db.New(cfg.Database.Path)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer database.Close()

	// Run migrations
	log.Printf("Running database migrations...")
	if err := db.RunMigrations(database); err != nil {
		log.Fatalf("Failed to run migrations: %v", err)
	}

	// Load or generate CA key pair
	log.Printf("Loading CA key pair from %s", cfg.CA.PrivateKeyPath)
	keyPair, err := ca.LoadOrGenerateKeyPair(
		cfg.CA.PrivateKeyPath,
		cfg.CA.PublicKeyPath,
		cfg.CA.KeyType,
	)
	if err != nil {
		log.Fatalf("Failed to load/generate CA key pair: %v", err)
	}
	log.Printf("CA key pair loaded successfully (type: %s)", keyPair.KeyType)

	// Initialize repositories
	userRepo := repository.NewUserRepository(database.DB)
	certRepo := repository.NewCertRepository(database.DB)
	tokenRepo := repository.NewTokenRepository(database.DB)
	serverRepo := repository.NewServerRepository(database.DB)
	auditRepo := repository.NewAuditRepository(database.DB)

	// Initialize policy validator
	validator := policy.NewValidator(cfg, certRepo)

	// Create HTTP server
	server := api.NewServer(
		cfg,
		keyPair,
		userRepo,
		certRepo,
		tokenRepo,
		serverRepo,
		auditRepo,
		validator,
	)

	// Setup graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	// Start server in a goroutine
	go func() {
		log.Printf("Starting HTTP server on %s", cfg.Server.ListenAddr)
		if err := server.Run(); err != nil {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()

	log.Printf("SSH CA Server is running")
	log.Printf("Press Ctrl+C to shutdown")

	// Wait for interrupt signal
	<-quit
	log.Printf("Shutting down server...")

	// Cleanup
	database.Close()

	log.Printf("Server stopped")
}
