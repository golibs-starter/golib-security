# Golib Security

Security solutions for Golang project. Includes: 
* Authentication (inspired from **Spring Security**): JWT, Basic Auth
* Authorization (inspired from **Spring Security**): RBAC
* Http Client Security:
  * Proxy
  * Authentication

### Setup instruction

Base setup, see [GoLib Instruction](https://gitlab.id.vin/vincart/golib/-/blob/develop/README.md)

Both `go get` and `go mod` are supported.

```shell
go get gitlab.id.vin/vincart/golib-security
```

### Usage

Using `fx.Option` to include dependencies for injection.

```go
package main

import (
  "gitlab.id.vin/vincart/golib-security"
  "gitlab.id.vin/vincart/golib/web/client"
  "go.uber.org/fx"
)

func main() {
  options := []fx.Option{

    // When you want to enable http security for your application
    golibsec.HttpSecurityOpt(),

    // When you want to register JWT authentication filter
    golibsec.JwtAuthFilterOpt(),

    // When you want to register Basic authentication filter
    golibsec.BasicAuthOpt(),

    // When you want to wrap default http client by a secured layer
    golibsec.SecuredHttpClientOpt(),
	
    // Example using http client
    fx.Provide(NewExampleService),
  }
}

type ExampleService struct {
  httpClient client.ContextualHttpClient
}

func NewExampleService(httpClient client.ContextualHttpClient) *ExampleService {
	return &ExampleService{httpClient: httpClient}
}
```

### Configuration

```yaml
vinid:
  security:
    http: # Configuration for HttpSecurityOpt()

      jwt: # Required when using JwtAuthFilterOpt()
        type: JWT_TOKEN_MOBILE # Currently, we support JWT_TOKEN_MOBILE
        publicKey: | # Public Key to verify JWT token
          -----BEGIN PUBLIC KEY-----
          MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgE...
          -----END PUBLIC KEY-----

      basicAuth: # Required when using BasicAuthOpt()
        users: # List of users with roles for basic auth
          - { username: "internal_service1", password: "secret", roles: [ "INTERNAL_SERVICE" ] }
          # Or you can use placeholder with format ${ENV_NAME}, it will be replaced by environment var
          - { username: "internal_service2", password: "${EXPOSED_INTERNAL_SERVICE_PWD}", roles: [ "INTERNAL_SERVICE" ] }
      
      publicUrls: # Define urls can be accessed without authentication
        - /actuator/health
        - /actuator/info
        - /swagger/*

      protectedUrls: # Define urls with required roles can be accessed with authentication
        - { urlPattern: "/v1/api-with-jwt-auth", method: POST, roles: [ "MOBILE_APP" ], unauthorizedWwwAuthenticateHeaders: [ "Bearer" ] }
        - { urlPattern: "/v1/api-with-basic-auth", method: POST, roles: [ "INTERNAL_SERVICE" ], unauthorizedWwwAuthenticateHeaders: [ "Basic" ] }

      client: # Required when using SecuredHttpClientOpt()
        basicAuth: # Define url with corresponding username password, these credentials will be auto attached to header before execute request.
          - { urlMatch: "https://foo.com/api/.*", username: "foo_user", password: "${FOO_SERVICE_PWD}" }
          - { urlMatch: "https://bar.com/api/.*", username: "bar_user", password: "${BAR_SERVICE_PWD}" }
```