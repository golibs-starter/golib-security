package filter

import (
	"context"
	"gitlab.id.vin/vincart/golib-security/web/constant"
	"gitlab.id.vin/vincart/golib/exception"
	"gitlab.id.vin/vincart/golib/web/resource"
	"net/http"
)

// SecurityFilter
// It's the part of security filter chain
type SecurityFilter func(next SecurityHandler) SecurityHandler

// SecurityHandler
// Handler function for security filter
type SecurityHandler func(w http.ResponseWriter, r *http.Request)

// CreateChainHandler Creates the security filter chain
func CreateChainHandler(filters []SecurityFilter, stoppingHandler SecurityHandler) SecurityHandler {
	var securityHandler = stoppingHandler
	for i := len(filters) - 1; i >= 0; i-- {
		securityHandler = filters[i](securityHandler)
	}
	return securityHandler
}

var UnauthorizedHandler SecurityHandler = func(w http.ResponseWriter, r *http.Request) {
	*r = *r.WithContext(context.WithValue(r.Context(), constant.UnauthorizedContext, true))
	resource.WriteError(w, exception.Unauthorized)
}
