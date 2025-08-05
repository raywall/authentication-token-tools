package ststoken

import (
	"github.com/golang-jwt/jwt/v5"
)

// CustomClaims defines the structure of the claims I use in the JWT.
// I created this custom type by embedding jwt.RegisteredClaims to include standard fields
// like issuer (iss) and expiration time (exp), and then added application-specific
// fields such as ClientID and Scopes for fine-grained access control.
type CustomClaims struct {
	// ClientID is the unique identifier for the client or user to whom the token was issued.
	ClientID string `json:"client_id"`
	// Scopes is a list of permissions granted to the token holder (e.g., "users:read").
	Scopes []string `json:"scopes"`
	// RegisteredClaims embeds standard JWT claims (iss, exp, iat, etc.).
	jwt.RegisteredClaims
}
