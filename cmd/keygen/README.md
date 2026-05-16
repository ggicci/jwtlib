# JWT Key Generation Tool

CLI tool for generating ECDSA key pairs used for JWT signing with the jwtlib package.

## Overview

The `keygen` tool generates:

- **Private Key** (`private_key.pem`): Used to sign JWTs
- **JWKS** (`jwks.json`): JSON Web Key Set containing the public key for JWT verification

## Algorithm

- **Type**: ECDSA (Elliptic Curve Digital Signature Algorithm)
- **Curve**: P-256 (also known as secp256r1 or prime256v1)
- **JWT Algorithm**: ES256
- **Key Size**: 256 bits

## Installation

```bash
go install github.com/ggicci/jwtlib/cmd/keygen@latest
```

Or build from source:

```bash
go build -o keygen ./cmd/keygen
```

## Usage

### Basic Usage

Generate keys with auto-generated key ID in `./keys/{kid}/`:

```bash
keygen
```

This creates:

```
./keys/
└── jwt-1234567890/
    ├── private_key.pem
    └── jwks.json
```

### Custom Base Directory

Specify the base directory (keys will still be organized by kid):

```bash
keygen -out ./etc/keys
```

Creates: `./etc/keys/{kid}/`

### Custom Key ID

Provide a custom key identifier (useful for key rotation):

```bash
keygen -kid my-service-prod-2024-01
```

Creates: `./keys/my-service-prod-2024-01/`

### Combined Example

```bash
keygen -out ./etc/keys -kid auth-service-dev
```

Creates: `./etc/keys/auth-service-dev/`

## Output Files

### private_key.pem

The ECDSA private key in PEM format. This file:

- Has restricted permissions (0600) - only readable by owner
- Must be kept secure and NEVER committed to version control
- Should be stored in environment variables or a secrets manager in production

Example PEM format:

```
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIINDO7VvJJKEMXRPWJPXGBKOV8RqVpAJVBMBHZF8Y+LDoAoGCCqGSM49
...
-----END EC PRIVATE KEY-----
```

### jwks.json

The JSON Web Key Set containing the public key. This file:

- Can be safely served publicly via HTTP endpoint
- Follows RFC 7517 JWKS format
- Includes key metadata for verification

Example format:

```json
{
  "keys": [
    {
      "kty": "EC",
      "use": "sig",
      "alg": "ES256",
      "kid": "jwt-1234567890",
      "crv": "P-256",
      "x": "base64url-encoded-x-coordinate",
      "y": "base64url-encoded-y-coordinate"
    }
  ]
}
```

## Integration with jwtlib

### Signing Service

1. Generate the key pair:

   ```bash
   keygen -kid my-service-dev -out ./keys
   ```

2. Load the private key:

   ```go
   import "github.com/ggicci/jwtlib"

   // Read private key from file
   privateKeyPEM, err := os.ReadFile("./keys/my-service-dev/private_key.pem")
   if err != nil {
       log.Fatal(err)
   }

   // Create signer
   signer, err := jwtlib.NewSigner(string(privateKeyPEM), "my-service-dev")
   if err != nil {
       log.Fatal(err)
   }

   // Issue tokens
   token, err := signer.IssueToken(userID, 1*time.Hour)
   ```

3. Serve the JWKS at `/.well-known/jwks.json` endpoint

### Verification Service

Other services can verify JWTs by:

1. Fetching the JWKS: `GET https://auth.example.com/.well-known/jwks.json`
2. Creating a verifier:
   ```go
   verifier, err := jwtlib.NewVerifier(jwtlib.VerifierConfig{
       JWKSURL:  "https://auth.example.com/.well-known/jwks.json",
       CacheTTL: 15 * time.Minute,
   })
   ```
3. Verifying tokens:
   ```go
   claims, err := verifier.VerifyToken(ctx, tokenString)
   ```

## Key Rotation

To rotate keys:

1. Generate a new key pair with a different `kid`:

   ```bash
   keygen -kid my-service-2024-02
   ```

2. Add the new public key to the JWKS (keeping old keys temporarily):

   ```json
   {
     "keys": [
       { "kid": "my-service-2024-01", ... },
       { "kid": "my-service-2024-02", ... }
     ]
   }
   ```

3. Update your service to use the new key ID and private key

4. After all old tokens expire, remove old keys from JWKS

## Security Best Practices

- **Never commit** `private_key.pem` to version control
- Add `private_key.pem` and `keys/` to `.gitignore`
- Store private keys in environment variables or secrets management systems in production
- Use file permissions 0600 for private key files
- Rotate keys periodically (e.g., every 6-12 months)
- Keep old public keys in JWKS until all tokens signed with them expire

## JWKS Fields Reference

| Field | Description                                        |
| ----- | -------------------------------------------------- |
| `kty` | Key Type - "EC" for Elliptic Curve                 |
| `use` | Public Key Use - "sig" for signature verification  |
| `alg` | Algorithm - "ES256" for ECDSA with SHA-256         |
| `kid` | Key ID - Identifier to match JWT header            |
| `crv` | Curve - "P-256" for the elliptic curve             |
| `x`   | X coordinate of the public key (base64url encoded) |
| `y`   | Y coordinate of the public key (base64url encoded) |
