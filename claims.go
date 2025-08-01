package ststoken

import (
	"github.com/golang-jwt/jwt/v5"
)

// CustomClaims custom framework to include scopes in the JWT token
type CustomClaims struct {
	ClientID string   `json:"client_id"`
	Scopes   []string `json:"scopes"`
	jwt.RegisteredClaims
}
