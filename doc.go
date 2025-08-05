// Copyright 2025 Raywall Malheiros
//
// Package ststoken provides a lightweight toolkit for handling authentication tokens.
// I designed this package to centralize and simplify the generation, validation, and
// manipulation of JSON Web Tokens (JWTs), particularly for use in microservices and
// serverless architectures. It acts as a small, self-contained Security Token Service (STS).
//
// Main Features:
//
//   - Secure JWT Generation: Creates cryptographically signed JWTs using the HS256 algorithm.
//   - Scope-Based Access Control: Embeds granular permissions (scopes) directly into the token.
//   - Straightforward Validation: Offers simple methods for validating a token's signature and claims,
//     ideal for use in middleware or AWS Lambda Authorizers.
//   - Secure Key Generation: Includes a utility to generate cryptographically secure keys.
//
// Typical Usage:
//
// I designed the TokenProvider as the central point of interaction:
//
//	// 1. Generate a secure key (in production, load this from a secret manager).
//	secret, _ := ststoken.GenerateRandomKey(32)
//
//	// 2. Create the provider.
//	provider := ststoken.NewTokenProvider(secret, "my-app-issuer")
//
//	// 3. Generate a token for a client with specific scopes.
//	scopes := []string{"users:read", "transactions:create"}
//	token, _ := provider.GenerateToken("client-id-123", scopes, 3600) // Expires in 1 hour
//
//	// 4. Validate the token and its scopes in a protected resource.
//	claims, _ := provider.ValidateToken(token)
//	if provider.VerifyScope(claims, "users:read") {
//	    // Allow access
//	}
//
// The secret key is critical for security and must be kept confidential.
package ststoken
