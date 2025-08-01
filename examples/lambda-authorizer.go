package main

import (
	"context"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	ststoken "github.com/raywall/authentication-token-tools"
)

var tokenProvider = ststoken.NewTokenProvider("your-secret-key-here", "api-gateway-authorizer")

func handler(ctx context.Context, event events.APIGatewayCustomAuthorizerRequest) (events.APIGatewayCustomAuthorizerResponse, error) {
	// Extract token from Authorization header
	token := event.AuthorizationToken

	// Token validation
	claims, err := tokenProvider.ValidateToken(token)
	if err != nil {
		return generatePolicy("user", "Deny", event.MethodArn), nil
	}

	// Check required scope (e.g. "transactions:read")
	requiredScope := "transactions:read"
	if !tokenProvider.VerifyScope(claims, requiredScope) {
		return generatePolicy(claims.ClientID, "Deny", event.MethodArn), nil
	}

	// Valid token and scope - allow access
	return generatePolicy(claims.ClientID, "Allow", event.MethodArn), nil
}

func generatePolicy(principalID, effect, resource string) events.APIGatewayCustomAuthorizerResponse {
	return events.APIGatewayCustomAuthorizerResponse{
		PrincipalID: principalID,
		PolicyDocument: events.APIGatewayCustomAuthorizerPolicy{
			Version: "2012-10-17",
			Statement: []events.IAMPolicyStatement{
				{
					Action:   []string{"execute-api:Invoke"},
					Effect:   effect,
					Resource: []string{resource},
				},
			},
		},
	}
}

func main() {
	lambda.Start(handler)
}
