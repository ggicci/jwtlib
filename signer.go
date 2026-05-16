package jwtlib

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// Signer handles JWT signing with ECDSA
type Signer struct {
	privateKey jwk.Key
	keyID      string
}

// NewSigner creates a new JWT signer with the provided private key
func NewSigner(privateKeyPEM, keyID string) (*Signer, error) {
	privateKey, err := parseECDSAPrivateKey(privateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	// Convert to JWK
	key, err := jwk.Import(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to import private key: %w", err)
	}

	// Set key ID
	if err := key.Set(jwk.KeyIDKey, keyID); err != nil {
		return nil, fmt.Errorf("failed to set key ID: %w", err)
	}

	// Set algorithm
	if err := key.Set(jwk.AlgorithmKey, jwa.ES256()); err != nil {
		return nil, fmt.Errorf("failed to set algorithm: %w", err)
	}

	return &Signer{
		privateKey: key,
		keyID:      keyID,
	}, nil
}

// SignToken creates a new JWT token for the given user ID with specified TTL
func (s *Signer) SignToken(token jwt.Token) (string, error) {
	if s == nil {
		return "", errors.New("jwt signer not initialized")
	}

	if userID, ok := token.Subject(); !ok || userID == "" {
		return "", errors.New("user ID cannot be empty")
	}

	// Sign the token
	signed, err := jwt.Sign(token, jwt.WithKey(jwa.ES256(), s.privateKey))
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return string(signed), nil
}

// parseECDSAPrivateKey parses an ECDSA private key from PEM format
func parseECDSAPrivateKey(pemData string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	if block.Type != "EC PRIVATE KEY" {
		return nil, fmt.Errorf("unexpected PEM block type: %s (expected EC PRIVATE KEY)", block.Type)
	}

	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse EC private key: %w", err)
	}

	return privateKey, nil
}
