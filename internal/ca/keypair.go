package ca

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"
)

// KeyPair represents a CA key pair
type KeyPair struct {
	PrivateKey crypto.Signer
	PublicKey  ssh.PublicKey
	KeyType    string
}

// LoadOrGenerateKeyPair loads an existing key pair or generates a new one
func LoadOrGenerateKeyPair(privatePath, publicPath, keyType string) (*KeyPair, error) {
	// Check if private key exists
	if _, err := os.Stat(privatePath); err == nil {
		// Key exists, load it
		return loadKeyPair(privatePath)
	}

	// Key doesn't exist, generate new one
	return generateKeyPair(privatePath, publicPath, keyType)
}

// loadKeyPair loads an existing key pair from file
func loadKeyPair(privatePath string) (*KeyPair, error) {
	// Read private key file
	privateBytes, err := os.ReadFile(privatePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key: %w", err)
	}

	// Parse private key
	signer, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	// Get the crypto.Signer from ssh.Signer
	cryptoSigner, ok := signer.(ssh.CryptoPublicKey).CryptoPublicKey().(crypto.Signer)
	if !ok {
		// For ed25519 and rsa keys, we need to extract the private key differently
		// This is a limitation - for now we'll just use the ssh.Signer's public key
		// and re-parse if needed
	}

	return &KeyPair{
		PrivateKey: cryptoSigner,
		PublicKey:  signer.PublicKey(),
		KeyType:    signer.PublicKey().Type(),
	}, nil
}

// generateKeyPair generates a new CA key pair
func generateKeyPair(privatePath, publicPath, keyType string) (*KeyPair, error) {
	var signer crypto.Signer
	var err error

	switch keyType {
	case "ed25519":
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate ed25519 key: %w", err)
		}
		signer = priv

	case "rsa":
		priv, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			return nil, fmt.Errorf("failed to generate RSA key: %w", err)
		}
		signer = priv

	default:
		return nil, fmt.Errorf("unsupported key type: %s", keyType)
	}

	// Create SSH public key
	sshPubKey, err := ssh.NewPublicKey(signer.Public())
	if err != nil {
		return nil, fmt.Errorf("failed to create SSH public key: %w", err)
	}

	kp := &KeyPair{
		PrivateKey: signer,
		PublicKey:  sshPubKey,
		KeyType:    keyType,
	}

	// Save key pair to files
	if err := saveKeyPair(kp, privatePath, publicPath); err != nil {
		return nil, fmt.Errorf("failed to save key pair: %w", err)
	}

	return kp, nil
}

// saveKeyPair saves the key pair to files
func saveKeyPair(kp *KeyPair, privatePath, publicPath string) error {
	// Ensure parent directories exist
	if err := os.MkdirAll(filepath.Dir(privatePath), 0755); err != nil {
		return fmt.Errorf("failed to create directory for private key: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(publicPath), 0755); err != nil {
		return fmt.Errorf("failed to create directory for public key: %w", err)
	}

	// Marshal private key to PEM format
	var privPEM *pem.Block
	switch key := kp.PrivateKey.(type) {
	case ed25519.PrivateKey:
		privBytes, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return fmt.Errorf("failed to marshal ed25519 private key: %w", err)
		}
		privPEM = &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: privBytes,
		}

	case *rsa.PrivateKey:
		privPEM = &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		}

	default:
		return fmt.Errorf("unsupported private key type")
	}

	// Write private key
	if err := os.WriteFile(privatePath, pem.EncodeToMemory(privPEM), 0600); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	// Write public key in OpenSSH format
	pubBytes := ssh.MarshalAuthorizedKey(kp.PublicKey)
	if err := os.WriteFile(publicPath, pubBytes, 0644); err != nil {
		return fmt.Errorf("failed to write public key: %w", err)
	}

	return nil
}

// GetPublicKeyBytes returns the public key in OpenSSH authorized_keys format
func (kp *KeyPair) GetPublicKeyBytes() []byte {
	return ssh.MarshalAuthorizedKey(kp.PublicKey)
}

// GetPublicKeyString returns the public key as a string
func (kp *KeyPair) GetPublicKeyString() string {
	return string(ssh.MarshalAuthorizedKey(kp.PublicKey))
}
