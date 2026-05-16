package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"
)

const (
	defaultAlgorithm = "ES256"
	defaultCurve     = "P-256"
)

// JWKS represents a JSON Web Key Set
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWK represents a JSON Web Key
type JWK struct {
	Kty string `json:"kty"` // Key Type
	Use string `json:"use"` // Public Key Use
	Alg string `json:"alg"` // Algorithm
	Kid string `json:"kid"` // Key ID
	Crv string `json:"crv"` // Curve (for EC keys)
	X   string `json:"x"`   // X Coordinate
	Y   string `json:"y"`   // Y Coordinate
}

func main() {
	var (
		baseDir string
		kid     string
	)

	flag.StringVar(&baseDir, "out", "./keys", "Base directory for generated keys (keys will be in {base}/{kid}/)")
	flag.StringVar(&kid, "kid", "", "Key ID (auto-generated if not provided)")
	flag.Parse()

	// Generate key ID if not provided
	if kid == "" {
		kid = generateKeyID()
	}

	// Create output directory: base/kid/
	outputDir := filepath.Join(baseDir, kid)
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		log.Fatalf("Failed to create output directory: %v", err)
	}

	// Generate ECDSA key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	// Save private key
	privateKeyPath := filepath.Join(outputDir, "private_key.pem")
	if err := savePrivateKey(privateKey, privateKeyPath); err != nil {
		log.Fatalf("Failed to save private key: %v", err)
	}

	// Generate and save JWKS
	jwksPath := filepath.Join(outputDir, "jwks.json")
	if err := saveJWKS(privateKey, kid, jwksPath); err != nil {
		log.Fatalf("Failed to save JWKS: %v", err)
	}

	fmt.Printf("✓ Key pair generated successfully!\n")
	fmt.Printf("  Algorithm: %s\n", defaultAlgorithm)
	fmt.Printf("  Curve: %s\n", defaultCurve)
	fmt.Printf("  Key ID: %s\n", kid)
	fmt.Printf("  Output Directory: %s\n", outputDir)
	fmt.Printf("  Private Key: %s\n", privateKeyPath)
	fmt.Printf("  JWKS: %s\n", jwksPath)
	fmt.Printf("\n⚠ WARNING: Keep the private key secure and NEVER commit it to version control!\n")
}

func generateKeyID() string {
	// Generate a time-based key ID for easy identification
	return fmt.Sprintf("jwt-%d", time.Now().Unix())
}

func savePrivateKey(key *ecdsa.PrivateKey, path string) error {
	// Marshal private key to PKCS8 format
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal private key: %w", err)
	}

	// Create PEM block
	pemBlock := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyBytes,
	}

	// Write to file with restricted permissions
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("create private key file: %w", err)
	}
	defer file.Close()

	if err := pem.Encode(file, pemBlock); err != nil {
		return fmt.Errorf("encode PEM: %w", err)
	}

	return nil
}

func saveJWKS(key *ecdsa.PrivateKey, kid, path string) error {
	// Extract public key coordinates
	publicKey := &key.PublicKey

	// Encode X and Y coordinates as base64url (unpadded)
	xBytes := publicKey.X.Bytes()
	yBytes := publicKey.Y.Bytes()

	// Ensure coordinates are 32 bytes (for P-256)
	xBytes = padBytes(xBytes, 32)
	yBytes = padBytes(yBytes, 32)

	jwk := JWK{
		Kty: "EC",
		Use: "sig",
		Alg: defaultAlgorithm,
		Kid: kid,
		Crv: defaultCurve,
		X:   base64.RawURLEncoding.EncodeToString(xBytes),
		Y:   base64.RawURLEncoding.EncodeToString(yBytes),
	}

	jwks := JWKS{
		Keys: []JWK{jwk},
	}

	// Marshal to JSON with indentation
	jsonBytes, err := json.MarshalIndent(jwks, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal JWKS: %w", err)
	}

	// Write to file
	if err := os.WriteFile(path, jsonBytes, 0644); err != nil {
		return fmt.Errorf("write JWKS file: %w", err)
	}

	return nil
}

// padBytes pads a byte slice to the desired length with leading zeros
func padBytes(b []byte, size int) []byte {
	if len(b) >= size {
		return b
	}
	padded := make([]byte, size)
	copy(padded[size-len(b):], b)
	return padded
}
