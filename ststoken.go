package ststoken

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// TokenProvider manages token creation and validation
type TokenProvider struct {
	secretKey []byte
	issuer    string
}

// NewTokenProvider creates a new TokenProvider instance
func NewTokenProvider(secretKey string, issuer string) *TokenProvider {
	return &TokenProvider{
		secretKey: []byte(secretKey),
		issuer:    issuer,
	}
}

// GenerateToken creates a new JWT token with scopes
func (p *TokenProvider) GenerateToken(clientID string, scopes []string, expiresIn int) (string, error) {
	if len(p.secretKey) < 32 {
		return "", errors.New("secret key must be at least 32 bytes long")
	}

	// Set expiration time
	expirationTime := time.Now().Add(time.Duration(expiresIn) * time.Second)

	// Creating claims with scopes
	claims := &CustomClaims{
		ClientID: clientID,
		Scopes:   scopes,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    p.issuer,
		},
	}

	// Create token with claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign token and return
	return token.SignedString(p.secretKey)
}

// ValidateToken validates a JWT token and returns the claims
func (p *TokenProvider) ValidateToken(tokenString string) (*CustomClaims, error) {
	// Token parse
	token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Check signature method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return p.secretKey, nil
	})

	if err != nil {
		return nil, err
	}

	// Validate claims
	if claims, ok := token.Claims.(*CustomClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.New("invalid token")
}

// VerifyScope checks if the token has a specific scope
func (p *TokenProvider) VerifyScope(claims *CustomClaims, requiredScope string) bool {
	for _, scope := range claims.Scopes {
		if scope == requiredScope {
			return true
		}
	}
	return false
}

// GenerateRandomKey generates a secure random secret key
func GenerateRandomKey(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(bytes), nil
}
