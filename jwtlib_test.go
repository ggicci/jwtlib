package jwtlib

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// testKeyPair holds a test ECDSA key pair and signer
type testKeyPair struct {
	privateKey *ecdsa.PrivateKey
	publicKey  *ecdsa.PublicKey
	keyID      string
	signer     *Signer
}

// generateTestKeyPair creates a test ECDSA key pair
func generateTestKeyPair() (*testKeyPair, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	// Convert private key to PEM format
	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	// Create signer
	keyID := "test-key-id"
	signer, err := NewSigner(string(privateKeyPEM), keyID)
	if err != nil {
		return nil, err
	}

	return &testKeyPair{
		privateKey: privateKey,
		publicKey:  &privateKey.PublicKey,
		keyID:      keyID,
		signer:     signer,
	}, nil
}

// createTestJWKS creates a JWKS response for testing
func (k *testKeyPair) createTestJWKS() ([]byte, error) {
	key, err := jwk.Import(k.publicKey)
	if err != nil {
		return nil, err
	}

	if err := key.Set(jwk.KeyIDKey, k.keyID); err != nil {
		return nil, err
	}

	if err := key.Set(jwk.AlgorithmKey, "ES256"); err != nil {
		return nil, err
	}

	if err := key.Set(jwk.KeyUsageKey, "sig"); err != nil {
		return nil, err
	}

	set := jwk.NewSet()
	if err := set.AddKey(key); err != nil {
		return nil, err
	}

	return json.Marshal(set)
}

func TestSigner(t *testing.T) {
	keyPair, err := generateTestKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate test key pair: %v", err)
	}

	t.Run("valid user ID", func(t *testing.T) {
		userID := "test-user-123"
		ttl := 1 * time.Hour

		// Build JWT token
		tok, err := jwt.NewBuilder().
			Subject(userID).
			IssuedAt(time.Now()).
			Expiration(time.Now().Add(ttl)).
			Build()
		if err != nil {
			t.Fatalf("Failed to build token: %v", err)
		}

		token, err := keyPair.signer.SignToken(tok)
		if err != nil {
			t.Fatalf("Failed to sign token: %v", err)
		}

		if token == "" {
			t.Error("Token should not be empty")
		}
	})

	t.Run("empty user ID", func(t *testing.T) {
		userID := ""
		ttl := 1 * time.Hour

		// Build JWT token with empty subject
		tok, err := jwt.NewBuilder().
			Subject(userID).
			IssuedAt(time.Now()).
			Expiration(time.Now().Add(ttl)).
			Build()
		if err != nil {
			t.Fatalf("Failed to build token: %v", err)
		}

		_, err = keyPair.signer.SignToken(tok)
		if err == nil {
			t.Error("Expected error for empty user ID, got nil")
		}
		if err != nil && err.Error() != "user ID cannot be empty" {
			t.Errorf("Expected 'user ID cannot be empty' error, got: %v", err)
		}
	})
}

func TestVerifier(t *testing.T) {
	keyPair, err := generateTestKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate test key pair: %v", err)
	}

	jwksData, err := keyPair.createTestJWKS()
	if err != nil {
		t.Fatalf("Failed to create test JWKS: %v", err)
	}

	// Create a test JWKS server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(jwksData)
	}))
	defer server.Close()

	verifier, err := NewVerifier(VerifierConfig{
		JWKSURL: server.URL,
	})
	if err != nil {
		t.Fatalf("Failed to create verifier: %v", err)
	}

	userID := "test-user-456"

	tests := []struct {
		name        string
		tokenFunc   func() (string, error)
		wantError   bool
		errorIs     error
		checkClaims func(*testing.T, *Claims)
	}{
		{
			name: "valid token",
			tokenFunc: func() (string, error) {
				tok, err := jwt.NewBuilder().
					Subject(userID).
					IssuedAt(time.Now()).
					Expiration(time.Now().Add(1 * time.Hour)).
					Build()
				if err != nil {
					return "", err
				}
				return keyPair.signer.SignToken(tok)
			},
			wantError: false,
			checkClaims: func(t *testing.T, claims *Claims) {
				if claims.Subject != userID {
					t.Errorf("Expected subject %s, got %s", userID, claims.Subject)
				}
				if claims.ExpiresAt.Before(time.Now()) {
					t.Errorf("Token should not be expired yet")
				}
			},
		},
		{
			name: "expired token",
			tokenFunc: func() (string, error) {
				tok, err := jwt.NewBuilder().
					Subject(userID).
					IssuedAt(time.Now().Add(-2 * time.Hour)).
					Expiration(time.Now().Add(-1 * time.Hour)).
					Build()
				if err != nil {
					return "", err
				}
				return keyPair.signer.SignToken(tok)
			},
			wantError: true,
			errorIs:   ErrTokenExpired,
		},
		{
			name: "malformed token",
			tokenFunc: func() (string, error) {
				return "not.a.valid.jwt", nil
			},
			wantError: true,
			errorIs:   ErrInvalidToken,
		},
		{
			name: "token with wrong signature",
			tokenFunc: func() (string, error) {
				// Create a different key pair with a wrong signer
				wrongKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					return "", err
				}

				// Convert wrong key to PEM
				wrongKeyBytes, err := x509.MarshalECPrivateKey(wrongKey)
				if err != nil {
					return "", err
				}

				wrongKeyPEM := pem.EncodeToMemory(&pem.Block{
					Type:  "EC PRIVATE KEY",
					Bytes: wrongKeyBytes,
				})

				// Create signer with wrong key but same key ID
				wrongSigner, err := NewSigner(string(wrongKeyPEM), keyPair.keyID)
				if err != nil {
					return "", err
				}

				// Build and sign token with wrong key (signature won't match public key in JWKS)
				tok, err := jwt.NewBuilder().
					Subject(userID).
					IssuedAt(time.Now()).
					Expiration(time.Now().Add(1 * time.Hour)).
					Build()
				if err != nil {
					return "", err
				}
				return wrongSigner.SignToken(tok)
			},
			wantError: true,
			errorIs:   ErrInvalidSignature,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokenString, err := tt.tokenFunc()
			if err != nil {
				t.Fatalf("Failed to create test token: %v", err)
			}

			claims, err := verifier.VerifyToken(context.Background(), tokenString)

			if tt.wantError {
				if err == nil {
					t.Errorf("VerifyToken() expected error, got nil")
					return
				}
				if tt.errorIs != nil && !errors.Is(err, tt.errorIs) {
					t.Errorf("VerifyToken() expected error %v, got %v", tt.errorIs, err)
				}
				return
			}

			if err != nil {
				t.Errorf("VerifyToken() unexpected error: %v", err)
				return
			}

			if claims == nil {
				t.Errorf("VerifyToken() returned nil claims")
				return
			}

			if tt.checkClaims != nil {
				tt.checkClaims(t, claims)
			}
		})
	}
}

func TestVerifier_RefreshJWKS(t *testing.T) {
	keyPair, err := generateTestKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate test key pair: %v", err)
	}

	jwksData, err := keyPair.createTestJWKS()
	if err != nil {
		t.Fatalf("Failed to create test JWKS: %v", err)
	}

	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.Header().Set("Content-Type", "application/json")
		w.Write(jwksData)
	}))
	defer server.Close()

	verifier, err := NewVerifier(VerifierConfig{
		JWKSURL:  server.URL,
		CacheTTL: 1 * time.Hour, // Long cache time
	})
	if err != nil {
		t.Fatalf("Failed to create verifier: %v", err)
	}

	initialRequests := requestCount

	// Manually refresh JWKS
	if err := verifier.RefreshJWKS(context.Background()); err != nil {
		t.Errorf("RefreshJWKS() unexpected error: %v", err)
	}

	if requestCount != initialRequests+1 {
		t.Errorf("Expected %d requests after manual refresh, got %d", initialRequests+1, requestCount)
	}
}

func TestVerifier_CacheTTL(t *testing.T) {
	keyPair, err := generateTestKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate test key pair: %v", err)
	}

	jwksData, err := keyPair.createTestJWKS()
	if err != nil {
		t.Fatalf("Failed to create test JWKS: %v", err)
	}

	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.Header().Set("Content-Type", "application/json")
		w.Write(jwksData)
	}))
	defer server.Close()

	verifier, err := NewVerifier(VerifierConfig{
		JWKSURL:  server.URL,
		CacheTTL: 100 * time.Millisecond, // Very short cache time
	})
	if err != nil {
		t.Fatalf("Failed to create verifier: %v", err)
	}

	initialRequests := requestCount
	userID := "test-user-789"

	// Create and verify a token
	tok, err := jwt.NewBuilder().
		Subject(userID).
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(1 * time.Hour)).
		Build()
	if err != nil {
		t.Fatalf("Failed to build token: %v", err)
	}

	token, err := keyPair.signer.SignToken(tok)
	if err != nil {
		t.Fatalf("Failed to sign token: %v", err)
	}

	if _, err := verifier.VerifyToken(context.Background(), token); err != nil {
		t.Errorf("First VerifyToken() unexpected error: %v", err)
	}

	// Should use cached JWKS
	if requestCount != initialRequests {
		t.Errorf("Expected cache to be used, but got additional request")
	}

	// Wait for cache to expire
	time.Sleep(150 * time.Millisecond)

	// Verify another token - should trigger refresh
	if _, err := verifier.VerifyToken(context.Background(), token); err != nil {
		t.Errorf("Second VerifyToken() unexpected error: %v", err)
	}

	if requestCount != initialRequests+1 {
		t.Errorf("Expected cache refresh, got %d requests (expected %d)", requestCount, initialRequests+1)
	}
}

func TestVerifier_FileJWKS(t *testing.T) {
	keyPair, err := generateTestKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate test key pair: %v", err)
	}

	jwksData, err := keyPair.createTestJWKS()
	if err != nil {
		t.Fatalf("Failed to create test JWKS: %v", err)
	}

	jwksPath := filepath.Join(t.TempDir(), "jwks.json")
	if err := os.WriteFile(jwksPath, jwksData, 0o600); err != nil {
		t.Fatalf("Failed to write JWKS file: %v", err)
	}

	verifier, err := NewVerifier(VerifierConfig{
		JWKSURL:  jwksPath,
		CacheTTL: 1 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Failed to create verifier: %v", err)
	}

	tok, err := jwt.NewBuilder().
		Subject("file-user-123").
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(1 * time.Hour)).
		Build()
	if err != nil {
		t.Fatalf("Failed to build token: %v", err)
	}

	token, err := keyPair.signer.SignToken(tok)
	if err != nil {
		t.Fatalf("Failed to sign token: %v", err)
	}

	if _, err := verifier.VerifyToken(context.Background(), token); err != nil {
		t.Fatalf("VerifyToken() unexpected error: %v", err)
	}
}
