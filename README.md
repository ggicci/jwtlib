# jwtlib

A production-ready, standalone Go library for JWT signing and verification using ECDSA (ES256).

## Features

- **JWT Signing**: Issue tokens with ECDSA private keys (ES256 algorithm)
- **JWT Verification**: Verify tokens using JWKS (JSON Web Key Set)
- **JWKS Caching**: Thread-safe caching with configurable TTL
- **Auto-refresh**: Automatically refreshes JWKS when cache expires or unknown key is encountered
- **Typed Errors**: Specific error types for different failure scenarios
- **Key Generation Tool**: CLI tool for generating ECDSA key pairs
- **Zero External Dependencies**: Only uses standard JWT libraries (`lestrrat-go/jwx/v3`)

## Installation

### Library

```bash
go get github.com/ggicci/jwtlib
```

### Key Generation Tool

```bash
go install github.com/ggicci/jwtlib/cmd/keygen@latest
```

See [cmd/keygen/README.md](cmd/keygen/README.md) for usage details.

## Usage

### Signing JWT Tokens

```go
package main

import (
    "time"

    "github.com/google/uuid"
    "github.com/ggicci/jwtlib"
)

func main() {
    // Load your ECDSA private key in PEM format
    privateKeyPEM := `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIIGLyHB...
-----END EC PRIVATE KEY-----`

    // Create a signer with your key ID
    signer, err := jwtlib.NewSigner(privateKeyPEM, "my-key-id")
    if err != nil {
        panic(err)
    }

    // Issue a token for a user with 1 hour TTL
    userID := uuid.New()
    token, err := signer.IssueToken(userID, 1*time.Hour)
    if err != nil {
        panic(err)
    }

    // token is a signed JWT string ready to send to clients
    println(token)
}
```

### Verifying JWT Tokens

```go
package main

import (
    "context"
    "fmt"

    "github.com/ggicci/jwtlib"
)

func main() {
    // Configure the verifier with your JWKS endpoint
    verifier, err := jwtlib.NewVerifier(jwtlib.VerifierConfig{
        JWKSURL:  "https://auth.example.com/.well-known/jwks.json",
        CacheTTL: 15 * time.Minute, // Optional, default: 15 minutes
    })
    if err != nil {
        panic(err)
    }

    // Verify a token
    tokenString := "eyJhbGciOiJFUzI1NiIsImtpZCI6..."
    claims, err := verifier.VerifyToken(context.Background(), tokenString)
    if err != nil {
        // Handle specific errors
        switch {
        case errors.Is(err, jwtlib.ErrTokenExpired):
            fmt.Println("Token has expired")
        case errors.Is(err, jwtlib.ErrInvalidSignature):
            fmt.Println("Invalid signature")
        case errors.Is(err, jwtlib.ErrInvalidToken):
            fmt.Println("Malformed token")
        default:
            fmt.Printf("Verification failed: %v\n", err)
        }
        return
    }

    // Access verified claims
    fmt.Printf("User ID: %s\n", claims.Subject)
    fmt.Printf("Issued at: %s\n", claims.IssuedAt)
    fmt.Printf("Expires at: %s\n", claims.ExpiresAt)
}
```

## API Reference

### Signer

#### `NewSigner(privateKeyPEM, keyID string) (*Signer, error)`

Creates a new JWT signer with the provided ECDSA private key in PEM format.

**Parameters:**

- `privateKeyPEM`: ECDSA private key in PEM format (must be "EC PRIVATE KEY")
- `keyID`: Key ID to include in JWT header (used for key rotation)

**Returns:**

- `*Signer`: Configured signer instance
- `error`: Error if key parsing fails

#### `(*Signer) IssueToken(userID uuid.UUID, ttl time.Duration) (string, error)`

Issues a new JWT token for the specified user with the given time-to-live.

**Parameters:**

- `userID`: User identifier (stored in `sub` claim)
- `ttl`: Time-to-live duration for the token

**Returns:**

- `string`: Signed JWT token
- `error`: Error if token creation or signing fails

**Token Claims:**

- `sub`: User ID (UUID string)
- `iat`: Issued at (Unix timestamp)
- `exp`: Expiration time (Unix timestamp)

### Verifier

#### `NewVerifier(config VerifierConfig) (*Verifier, error)`

Creates a new JWT verifier that fetches and caches JWKS.

**Parameters:**

- `config.JWKSURL`: URL to fetch JWKS from (required)
- `config.CacheTTL`: How long to cache JWKS (default: 15 minutes)
- `config.HTTPClient`: HTTP client for JWKS requests (default: 10s timeout client)

**Returns:**

- `*Verifier`: Configured verifier instance
- `error`: Error if initial JWKS fetch fails

#### `(*Verifier) VerifyToken(ctx context.Context, tokenString string) (*Claims, error)`

Verifies a JWT token and extracts claims.

**Parameters:**

- `ctx`: Context for cancellation and timeouts
- `tokenString`: JWT token to verify

**Returns:**

- `*Claims`: Verified token claims
- `error`: Typed error indicating failure reason

**Errors:**

- `ErrTokenExpired`: Token has expired
- `ErrInvalidSignature`: Signature verification failed
- `ErrInvalidToken`: Token is malformed or has invalid claims
- `ErrKeyNotFound`: Key ID from token not found in JWKS

#### `(*Verifier) RefreshJWKS(ctx context.Context) error`

Manually triggers a JWKS refresh (useful for testing or forcing updates).

**Parameters:**

- `ctx`: Context for cancellation and timeouts

**Returns:**

- `error`: Error if JWKS fetch or parsing fails

### Claims

```go
type Claims struct {
    Subject   uuid.UUID // User ID
    IssuedAt  time.Time // Token issue time
    ExpiresAt time.Time // Token expiration time
}
```

## Error Handling

The library provides typed errors for different failure scenarios:

```go
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
```

Use `errors.Is()` to check for specific error types:

```go
if errors.Is(err, jwtlib.ErrTokenExpired) {
    // Handle expired token
}
```

## Security Best Practices

### Key Management

1. **Never commit private keys** to version control
2. **Rotate keys regularly** using the `kid` (key ID) parameter
3. **Use environment variables** or secret management systems for keys
4. **Generate keys with sufficient entropy** (P-256 curve for ES256)

### Token Validation

1. **Always verify tokens** before trusting claims
2. **Check expiration times** (handled automatically by this library)
3. **Use appropriate TTLs** (shorter for sensitive operations)
4. **Validate the `sub` claim** matches expected format (UUID)

### JWKS Caching

1. **Configure appropriate cache TTL** (balance between performance and security)
2. **Monitor JWKS endpoint availability** (verifier fetches on startup)
3. **Handle refresh failures gracefully** (library auto-retries on unknown key)

## Thread Safety

All operations are thread-safe:

- `Signer.IssueToken()` can be called concurrently
- `Verifier.VerifyToken()` uses read locks for cached JWKS
- `Verifier.RefreshJWKS()` uses write locks for cache updates

## Performance Considerations

### JWKS Caching

The verifier caches JWKS in memory with the following behavior:

1. **Initial fetch**: JWKS fetched on verifier creation
2. **Cache hit**: No network request if cache is fresh
3. **Cache miss**: Automatic refresh when TTL expires
4. **Unknown key**: Auto-refresh if token uses unknown `kid`

### Token Verification

Token verification is fast:

- Cached JWKS lookup: O(1)
- Signature verification: ~0.1ms for ES256
- No database or network calls for cached keys

## Testing

Run tests with:

```bash
go test -v
```

Tests cover:

- Valid token signing and verification
- Expired token detection
- Malformed token handling
- Wrong signature detection
- JWKS caching behavior
- Manual JWKS refresh

## Requirements

- Go 1.25.1 or later
- Dependencies:
  - `github.com/google/uuid` v1.6.0
  - `github.com/lestrrat-go/jwx/v3` v3.0.11

## License

MIT License

## Contributing

Contributions are welcome! Please ensure:

- All tests pass (`go test ./...`)
- Code is formatted (`go fmt ./...`)
- New features include tests
- Documentation is updated
