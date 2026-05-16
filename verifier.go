package jwtlib

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

var (
	// ErrInvalidToken indicates the token is malformed or invalid
	ErrInvalidToken = errors.New("invalid token")
	// ErrTokenExpired indicates the token has expired
	ErrTokenExpired = errors.New("token expired")
	// ErrInvalidSignature indicates the signature verification failed
	ErrInvalidSignature = errors.New("invalid signature")
	// ErrKeyNotFound indicates the key ID from token header not found in JWKS
	ErrKeyNotFound = errors.New("key not found in JWKS")
)

// Claims represents the JWT claims extracted from a verified token
type Claims struct {
	Subject   string // User ID
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// Verifier verifies JWT tokens using JWKS from the auth service
type Verifier struct {
	jwksURL     string
	httpClient  *http.Client
	jwksCache   jwk.Set
	cacheMutex  sync.RWMutex
	cacheTTL    time.Duration
	lastCacheAt time.Time
}

// VerifierConfig configures the JWT verifier
type VerifierConfig struct {
	// JWKSURL is the URL to fetch the JWKS from (e.g., "https://auth.example.com/.well-known/jwks.json")
	JWKSURL string
	// CacheTTL is how long to cache the JWKS before refetching (default: 15 minutes)
	CacheTTL time.Duration
	// HTTPClient is the HTTP client to use for fetching JWKS (default: http.DefaultClient)
	HTTPClient *http.Client
}

// NewVerifier creates a new JWT verifier
func NewVerifier(config VerifierConfig) (*Verifier, error) {
	if config.JWKSURL == "" {
		return nil, errors.New("JWKS URL is required")
	}

	if config.CacheTTL == 0 {
		config.CacheTTL = 15 * time.Minute
	}

	if config.HTTPClient == nil {
		config.HTTPClient = &http.Client{
			Timeout: 10 * time.Second,
		}
	}

	v := &Verifier{
		jwksURL:    config.JWKSURL,
		httpClient: config.HTTPClient,
		cacheTTL:   config.CacheTTL,
	}

	// Fetch JWKS on initialization
	if err := v.refreshJWKS(context.Background()); err != nil {
		return nil, fmt.Errorf("failed to fetch initial JWKS: %w", err)
	}

	return v, nil
}

// VerifyToken verifies a JWT token and returns the claims
func (v *Verifier) VerifyToken(ctx context.Context, tokenString string) (*Claims, error) {
	// Ensure JWKS is up to date
	if err := v.ensureJWKSFresh(ctx); err != nil {
		return nil, fmt.Errorf("failed to refresh JWKS: %w", err)
	}

	// Get the current JWKS
	v.cacheMutex.RLock()
	keySet := v.jwksCache
	v.cacheMutex.RUnlock()

	// Parse and verify the token using the JWKS
	verified, err := jwt.ParseString(
		tokenString,
		jwt.WithKeySet(keySet),
		jwt.WithValidate(true),
		jwt.WithAcceptableSkew(5*time.Minute), // allow time difference between servers
	)
	if err != nil {
		// Check if the error is due to token expiration
		if errors.Is(err, jwt.TokenExpiredError()) {
			return nil, ErrTokenExpired
		}

		// Check if it's a verification error (signature mismatch) - check this BEFORE parse error
		// because jwt.ParseString wraps jws.VerificationError in a parse error
		if errors.Is(err, jws.VerificationError()) {
			return nil, fmt.Errorf("%w: %v", ErrInvalidSignature, err)
		}

		// Check if it's a parse error (malformed token)
		if errors.Is(err, jwt.ParseError()) {
			return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
		}

		// Could be key not found, let's try refreshing JWKS once
		if refreshErr := v.refreshJWKS(ctx); refreshErr == nil {
			v.cacheMutex.RLock()
			keySet = v.jwksCache
			v.cacheMutex.RUnlock()

			// Try again with refreshed JWKS
			verified, err = jwt.ParseString(
				tokenString,
				jwt.WithKeySet(keySet),
				jwt.WithValidate(true),
			)
			if err != nil {
				if errors.Is(err, jwt.TokenExpiredError()) {
					return nil, ErrTokenExpired
				}
				if errors.Is(err, jws.VerificationError()) {
					return nil, fmt.Errorf("%w: %v", ErrInvalidSignature, err)
				}
				if errors.Is(err, jwt.ParseError()) {
					return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
				}
				return nil, fmt.Errorf("%w: %v", ErrInvalidSignature, err)
			}
		} else {
			return nil, fmt.Errorf("%w: %v", ErrInvalidSignature, err)
		}
	}

	// Extract claims
	subject, ok := verified.Subject()
	if !ok || subject == "" {
		return nil, fmt.Errorf("%w: missing subject claim", ErrInvalidToken)
	}

	issuedAt, _ := verified.IssuedAt()
	expiresAt, _ := verified.Expiration()

	return &Claims{
		Subject:   subject,
		IssuedAt:  issuedAt,
		ExpiresAt: expiresAt,
	}, nil
}

// ensureJWKSFresh checks if the JWKS cache needs refreshing
func (v *Verifier) ensureJWKSFresh(ctx context.Context) error {
	v.cacheMutex.RLock()
	needsRefresh := time.Since(v.lastCacheAt) > v.cacheTTL
	v.cacheMutex.RUnlock()

	if needsRefresh {
		return v.refreshJWKS(ctx)
	}

	return nil
}

// refreshJWKS fetches the latest JWKS from the auth service
func (v *Verifier) refreshJWKS(ctx context.Context) error {
	body, err := v.loadJWKS(ctx)
	if err != nil {
		return err
	}

	// Parse JWKS
	set, err := jwk.Parse(body)
	if err != nil {
		return fmt.Errorf("failed to parse JWKS: %w", err)
	}

	v.cacheMutex.Lock()
	v.jwksCache = set
	v.lastCacheAt = time.Now()
	v.cacheMutex.Unlock()

	return nil
}

func (v *Verifier) loadJWKS(ctx context.Context) ([]byte, error) {
	if !strings.HasPrefix(v.jwksURL, "http://") && !strings.HasPrefix(v.jwksURL, "https://") {
		data, err := os.ReadFile(v.jwksURL)
		if err != nil {
			return nil, fmt.Errorf("failed to read JWKS file: %w", err)
		}
		return data, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.jwksURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	return body, nil
}

// RefreshJWKS manually triggers a JWKS refresh (useful for testing or forcing updates)
func (v *Verifier) RefreshJWKS(ctx context.Context) error {
	return v.refreshJWKS(ctx)
}
