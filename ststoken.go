package ststoken

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// TokenProvider is the central struct for managing token operations.
// I designed it to encapsulate the signing key and issuer details, providing a clear
// and secure interface for token creation and validation.
type TokenProvider struct {
	secretKey []byte
	issuer    string
}

// NewTokenProvider is the constructor for creating a new TokenProvider instance.
// It requires a secret key for signing tokens and an issuer string to identify
// who issued the tokens.
func NewTokenProvider(secretKey string, issuer string) *TokenProvider {
	return &TokenProvider{
		secretKey: []byte(secretKey),
		issuer:    issuer,
	}
}

// GenerateToken creates a new signed JWT for a given client with specific scopes.
// It takes a clientID, a slice of scope strings, and an expiration time in seconds.
// A security check ensures the secret key is of a sufficient length.
func (p *TokenProvider) GenerateToken(clientID string, scopes []string, expiresIn int) (string, error) {
	// I've added this check to enforce a minimum key length, which is a security best practice
	// for HMAC-based algorithms like HS256.
	if len(p.secretKey) < 32 {
		return "", errors.New("secret key must be at least 32 bytes long")
	}

	// Define the token's expiration time.
	expirationTime := time.Now().Add(time.Duration(expiresIn) * time.Second)

	// Construct the custom claims for the token.
	claims := &CustomClaims{
		ClientID: clientID,
		Scopes:   scopes,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    p.issuer,
		},
	}

	// Create a new token object with the HS256 signing method and my custom claims.
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign the token with the secret key to generate the final token string.
	return token.SignedString(p.secretKey)
}

// ValidateToken parses a token string, verifies its signature and standard claims (like expiration),
// and returns the CustomClaims if the token is valid.
func (p *TokenProvider) ValidateToken(tokenString string) (*CustomClaims, error) {
	// The jwt.ParseWithClaims function requires a keyfunc callback. I use this callback
	// to supply the secret key for signature verification and to ensure the token's signing
	// algorithm is the one I expect (HS256). This prevents "alg: none" attacks.
	token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return p.secretKey, nil
	})

	if err != nil {
		return nil, err // This can be due to an invalid signature, expired token, etc.
	}

	// After parsing, I perform a final check to ensure the claims can be cast to my
	// CustomClaims type and that the token as a whole is considered valid by the library.
	if claims, ok := token.Claims.(*CustomClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.New("invalid token")
}

// VerifyScope is a utility method to check if a specific, required scope
// exists within the token's claims. This is a common pattern for authorization.
func (p *TokenProvider) VerifyScope(claims *CustomClaims, requiredScope string) bool {
	for _, scope := range claims.Scopes {
		if scope == requiredScope {
			return true
		}
	}
	return false
}

// GenerateRandomKey is a helper function that generates a cryptographically secure
// random key of a specified length and returns it as a base64 encoded string.
// This is the recommended way to create secret keys for production environments.
func GenerateRandomKey(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(bytes), nil
}
