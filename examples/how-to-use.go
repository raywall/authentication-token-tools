package main

import (
	"fmt"
	"log"

	ststoken "github.com/raywall/authentication-token-tools"
)

func ExampleTokenProvider() {
	// Generate a secure secret key (in production, store securely)
	key, err := ststoken.GenerateRandomKey(32)
	if err != nil {
		log.Fatal(err)
	}

	// Create token provider
	provider := ststoken.NewTokenProvider(key, "my-sts-service")

	// Generate token with scopes
	scopes := []string{"transactions:read", "transactions:write", "users:read"}
	token, err := provider.GenerateToken("client-123", scopes, 3600)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Generated token: %s\n", token)

	// Token validation
	claims, err := provider.ValidateToken(token)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Token validated for client: %s\n", claims.ClientID)

	// Scope validation
	hasScope := provider.VerifyScope(claims, "transactions:write")
	fmt.Printf("Has transactions:write scope: %v\n", hasScope)

	// Output:
	// Generated token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
	// Token validated for client: client-123
	// Has transactions:write scope: true
}
