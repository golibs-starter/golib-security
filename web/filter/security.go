package filter

import (
	"gitlab.com/golibs-starter/golib-security/web/auth/authen"
	"net/http"
)

// AuthenticationFilter
// It's the part of security filter chain
type AuthenticationFilter func(next AuthenticationHandler) AuthenticationHandler

// AuthenticationHandler
// Handler function for authentication filter
type AuthenticationHandler func(w http.ResponseWriter, r *http.Request) authen.Authentication

// CreateAuthenticationHandler Creates the filter chain,
// and returns the authentication handler
func CreateAuthenticationHandler(filters []AuthenticationFilter, stoppingHandler AuthenticationHandler) AuthenticationHandler {
	var securityHandler = stoppingHandler
	for i := len(filters) - 1; i >= 0; i-- {
		securityHandler = filters[i](securityHandler)
	}
	return securityHandler
}

var UnauthorizedHandler AuthenticationHandler = func(w http.ResponseWriter, r *http.Request) authen.Authentication {
	// Returns nil to indicates that the request is unauthenticated
	return nil
}
