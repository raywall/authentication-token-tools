# Authentication Token Tools (`ststoken`)

Olá! Eu sou Raywall Malheiros, e este é um projeto que criei para simplificar a forma como lidamos com autenticação e autorização em aplicações Go modernas. O `authentication-token-tools` é um toolkit leve que fornece as ferramentas essenciais para gerar e validar JSON Web Tokens (JWTs) de forma segura e eficiente.

A minha intenção foi criar uma biblioteca pequena, com dependências mínimas, focada em resolver um problema comum: a necessidade de um serviço de tokens de segurança (STS) simples para microserviços e arquiteturas serverless.

## O que a biblioteca faz?

Esta biblioteca permite que você:

- Gere JWTs assinados com o algoritmo `HS256`.
- Incorpore dados personalizados nos tokens, como um `ClientID` e uma lista de `scopes` (permissões).
- Valide tokens de forma segura, verificando a assinatura, o tempo de expiração e o emissor.
- Verifique facilmente se um token possui um `scope` específico para controle de acesso granular.
- Crie chaves secretas seguras para uso em produção.

## Instalação

Para adicionar a biblioteca ao seu projeto, execute:

```bash
go get [github.com/raywall/authentication-token-tools](https://github.com/raywall/authentication-token-tools)
```

## Como Usar

A seguir, apresento os principais cenários de uso que eu projetei para a biblioteca.

### Exemplo 1: Geração e Validação Básica de Token

Este é o fluxo de trabalho mais comum: criar um token para um cliente e depois validá-lo em um recurso protegido.

```go
package main

import (
    "fmt"
    "log"
    ststoken "[github.com/raywall/authentication-token-tools](https://github.com/raywall/authentication-token-tools)"
)

func main() {
    // 1. Gere uma chave secreta segura. Em um ambiente de produção,
    // esta chave deve ser carregada de um local seguro, como o AWS Secrets Manager
    // ou variáveis de ambiente, e não gerada a cada execução.
    secretKey, err := ststoken.GenerateRandomKey(32) // 32 bytes for HS256
    if err != nil {
        log.Fatalf("Failed to generate secret key: %v", err)
    }

    // 2. Crie uma instância do TokenProvider com a chave e um nome de emissor.
    provider := ststoken.NewTokenProvider(secretKey, "my-sts-service")

    // 3. Gere um novo token para um cliente específico com um conjunto de permissões (scopes).
    // O token expira em 3600 segundos (1 hora).
    clientID := "client-123"
    scopes := []string{"transactions:read", "transactions:write", "users:read"}
    token, err := provider.GenerateToken(clientID, scopes, 3600)
    if err != nil {
        log.Fatalf("Failed to generate token: %v", err)
    }
    fmt.Printf("Token Gerado: %s\n\n", token)

    // --- Em um serviço ou endpoint protegido ---

    // 4. Valide o token recebido.
    claims, err := provider.ValidateToken(token)
    if err != nil {
        log.Fatalf("Token validation failed: %v", err)
    }
    fmt.Printf("Token validado com sucesso para o cliente: %s\n", claims.ClientID)
    fmt.Printf("Emissor do token: %s\n", claims.Issuer)

    // 5. Verifique se o token tem a permissão necessária para a operação.
    requiredScope := "transactions:write"
    hasScope := provider.VerifyScope(claims, requiredScope)
    fmt.Printf("Possui o scope '%s'? %v\n", requiredScope, hasScope)
}
```

### Exemplo 2: Integração com AWS Lambda Authorizer

Eu projetei a biblioteca pensando especificamente neste caso de uso, que é muito comum para proteger APIs no Amazon API Gateway. O Lambda Authorizer valida o token antes de encaminhar a requisição para o serviço de destino.

```go
package main

import (
    "context"
    "os"

    "[github.com/aws/aws-lambda-go/events](https://github.com/aws/aws-lambda-go/events)"
    "[github.com/aws/aws-lambda-go/lambda](https://github.com/aws/aws-lambda-go/lambda)"
    ststoken "[github.com/raywall/authentication-token-tools](https://github.com/raywall/authentication-token-tools)"
)

// O provedor de token é inicializado globalmente para reutilização entre as invocações do Lambda.
// Em um cenário real, a chave secreta viria de uma variável de ambiente.
var tokenProvider = ststoken.NewTokenProvider(
    os.Getenv("JWT_SECRET_KEY"),
    "api-gateway-authorizer",
)

// O handler do Lambda Authorizer.
func handler(ctx context.Context, event events.APIGatewayCustomAuthorizerRequest) (events.APIGatewayCustomAuthorizerResponse, error) {
    // 1. Extrai o token do cabeçalho "Authorization".
    token := event.AuthorizationToken

    // 2. Valida o token. Se falhar, nega o acesso.
    claims, err := tokenProvider.ValidateToken(token)
    if err != nil {
        // Nega o acesso gerando uma política IAM de "Deny".
        return generatePolicy("user", "Deny", event.MethodArn), nil
    }

    // 3. Verifica se o token contém o scope necessário para acessar este recurso.
    // O scope necessário pode vir da configuração da rota no API Gateway, por exemplo.
    requiredScope := "transactions:read"
    if !tokenProvider.VerifyScope(claims, requiredScope) {
        return generatePolicy(claims.ClientID, "Deny", event.MethodArn), nil
    }

    // 4. Se o token é válido e possui o scope, permite o acesso.
    // O ClientID do token é usado como o principal na política IAM.
    return generatePolicy(claims.ClientID, "Allow", event.MethodArn), nil
}

// generatePolicy é uma função auxiliar para criar a resposta da política IAM.
func generatePolicy(principalID, effect, resource string) events.APIGatewayCustomAuthorizerResponse {
    // ... (implementação da função)
}

func main() {
    lambda.Start(handler)
}
```

## Nota de Segurança

A segurança dos seus tokens depende inteiramente da confidencialidade da sua `secretKey`.

- **NUNCA** codifique a chave secreta diretamente no seu código-fonte.
- Use uma chave com pelo menos 32 bytes (256 bits) de entropia para o algoritmo `HS256`. A função `GenerateRandomKey(32)` é ideal para isso.
- Armazene sua chave secreta de forma segura, utilizando serviços como AWS Secrets Manager, HashiCorp Vault ou variáveis de ambiente injetadas no seu ambiente de execução.

Espero que esta biblioteca seja útil!

Atenciosamente,

**Raywall Malheiros**
