package main

import (
	"fmt"
	"log"
	"os"

	"github.com/adamscao/caserver/internal/auth"
	"github.com/adamscao/caserver/internal/config"
	"github.com/adamscao/caserver/internal/db"
	"github.com/adamscao/caserver/internal/db/repository"
	"github.com/adamscao/caserver/internal/models"
	"github.com/spf13/cobra"
)

var (
	configPath string
	cfg        *config.Config
	database   *db.DB
)

var rootCmd = &cobra.Command{
	Use:   "admin",
	Short: "SSH CA Server administration tool",
	Long:  "Administrative tool for managing SSH CA Server users, tokens, and audit logs",
}

var userCmd = &cobra.Command{
	Use:   "user",
	Short: "Manage users",
}

var userCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new user",
	RunE:  createUser,
}

var userListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all users",
	RunE:  listUsers,
}

var (
	username       string
	password       string
	generateTOTP   bool
	totpSecret     string
	enabled        bool
	maxCertsPerDay int
)

func init() {
	// Root flags
	rootCmd.PersistentFlags().StringVarP(&configPath, "config", "c", "/etc/ssh-ca/config.yaml", "Config file path")

	// User create flags
	userCreateCmd.Flags().StringVarP(&username, "username", "u", "", "Username (required)")
	userCreateCmd.Flags().StringVarP(&password, "password", "p", "", "Password (required)")
	userCreateCmd.Flags().BoolVar(&generateTOTP, "generate-totp", false, "Generate TOTP secret automatically")
	userCreateCmd.Flags().StringVar(&totpSecret, "totp-secret", "", "TOTP secret (required if not generating)")
	userCreateCmd.Flags().BoolVar(&enabled, "enabled", true, "Enable user account")
	userCreateCmd.Flags().IntVar(&maxCertsPerDay, "max-certs-per-day", 10, "Maximum certificates per day")

	userCreateCmd.MarkFlagRequired("username")
	userCreateCmd.MarkFlagRequired("password")

	// Add commands
	userCmd.AddCommand(userCreateCmd)
	userCmd.AddCommand(userListCmd)
	rootCmd.AddCommand(userCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func initDB() error {
	// Load configuration
	var err error
	cfg, err = config.LoadWithEnv(configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Connect to database
	database, err = db.New(cfg.Database.Path)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}

	return nil
}

func createUser(cmd *cobra.Command, args []string) error {
	if err := initDB(); err != nil {
		return err
	}
	defer database.Close()

	// Get or generate TOTP secret
	var secret string
	if generateTOTP {
		var err error
		secret, err = auth.GenerateTOTPSecret()
		if err != nil {
			return fmt.Errorf("failed to generate TOTP secret: %w", err)
		}
		log.Printf("Generated TOTP secret: %s", secret)
	} else {
		if totpSecret == "" {
			return fmt.Errorf("either --generate-totp or --totp-secret must be provided")
		}
		secret = totpSecret
	}

	// Hash password
	passwordHash, err := auth.HashPassword(password)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	// Create user
	userRepo := repository.NewUserRepository(database.DB)
	user := &models.User{
		Username:       username,
		PasswordHash:   passwordHash,
		TOTPSecret:     secret,
		Enabled:        enabled,
		MaxCertsPerDay: maxCertsPerDay,
	}

	if err := userRepo.Create(user); err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	// Generate QR URL
	qrURL := auth.GenerateQRCodeURL(secret, username, "SSH-CA")

	fmt.Printf("\nUser created successfully!\n")
	fmt.Printf("User ID: %d\n", user.ID)
	fmt.Printf("Username: %s\n", user.Username)
	fmt.Printf("Enabled: %t\n", user.Enabled)
	fmt.Printf("Max certs per day: %d\n", user.MaxCertsPerDay)
	fmt.Printf("\nTOTP Secret: %s\n", secret)
	fmt.Printf("TOTP QR URL: %s\n", qrURL)
	fmt.Printf("\nScan the QR URL with a TOTP app (Google Authenticator, Authy, etc.)\n")

	return nil
}

func listUsers(cmd *cobra.Command, args []string) error {
	if err := initDB(); err != nil {
		return err
	}
	defer database.Close()

	userRepo := repository.NewUserRepository(database.DB)
	users, err := userRepo.List()
	if err != nil {
		return fmt.Errorf("failed to list users: %w", err)
	}

	if len(users) == 0 {
		fmt.Println("No users found")
		return nil
	}

	fmt.Printf("\nTotal users: %d\n\n", len(users))
	fmt.Printf("%-5s %-20s %-10s %-15s %s\n", "ID", "Username", "Enabled", "Max Certs/Day", "Created")
	fmt.Println("--------------------------------------------------------------------------------")

	for _, user := range users {
		enabledStr := "No"
		if user.Enabled {
			enabledStr = "Yes"
		}
		fmt.Printf("%-5d %-20s %-10s %-15d %s\n",
			user.ID,
			user.Username,
			enabledStr,
			user.MaxCertsPerDay,
			user.CreatedAt.Format("2006-01-02 15:04:05"),
		)
	}

	return nil
}
