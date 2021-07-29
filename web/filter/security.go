package filter

import (
	"gitlab.id.vin/vincart/golib-security/web/auth/authen"
	"net/http"
)

// SecurityFilter
// It's the part of security filter chain
type SecurityFilter func(next SecurityHandler) SecurityHandler

// SecurityHandler
// Handler function for security filter
type SecurityHandler func(w http.ResponseWriter, r *http.Request) authen.Authentication

// CreateChainHandler Creates the security filter chain
func CreateChainHandler(filters []SecurityFilter, stoppingHandler SecurityHandler) SecurityHandler {
	var securityHandler = stoppingHandler
	for i := len(filters) - 1; i >= 0; i-- {
		securityHandler = filters[i](securityHandler)
	}
	return securityHandler
}

var UnauthorizedHandler SecurityHandler = func(w http.ResponseWriter, r *http.Request) authen.Authentication {
	// Returns nil to indicates that the request is unauthenticated
	return nil
}
