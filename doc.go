// Package ststoken provides utilities for generating and validating STS tokens with scopes
//
// Main features:
// - Generation of signed JWT tokens with specific scopes
// - Token validation in Lambda Authorizers
// - Scope verification for access control
// - Token lifetime management
//
// Typical usage:
//
// provider := ststoken.NewTokenProvider("secret-key-32bytes", "issuer-name")
// token, err := provider.GenerateToken("client-id", []string{"scope1", "scope2"}, 3600)
// claims, err := provider.ValidateToken(token)
// hasScope := provider.VerifyScope(claims, "required-scope")
//
// The secret key must be kept secret and stored securely.
package ststoken
