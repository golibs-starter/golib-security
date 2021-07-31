package middleware

import (
	"context"
	"gitlab.id.vin/vincart/golib-security/utils"
	"gitlab.id.vin/vincart/golib-security/web/auth/authen"
	"gitlab.id.vin/vincart/golib-security/web/auth/authorization"
	"gitlab.id.vin/vincart/golib-security/web/constant"
	"gitlab.id.vin/vincart/golib-security/web/filter"
	"gitlab.id.vin/vincart/golib/exception"
	"gitlab.id.vin/vincart/golib/web/log"
	"gitlab.id.vin/vincart/golib/web/resource"
	"net/http"
)

func Auth(
	authManager authen.AuthenticationManager,
	accessDecisionManager authorization.AccessDecisionManager,
	filters []filter.SecurityFilter,
) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			protectedUrl, protected := isProtectedRequest(r)
			if !protected {
				log.Debug(r.Context(), "Authentication is not required for this request, skip")
				next.ServeHTTP(w, r)
				return
			}

			// Create and run the security filter chain
			filterChainHandler := filter.CreateChainHandler(filters, filter.UnauthorizedHandler)
			authentication := filterChainHandler(w, r)
			if authentication == nil {
				log.Info(r.Context(), "Authentication is required to access this resource")
				resource.WriteError(w, exception.Unauthorized)
				return
			}

			authentication, err := authManager.Authenticate(authentication)
			if err != nil {
				log.Info(r.Context(), "Authentication failed, error [%s]", err.Error())
				resource.WriteError(w, exception.Unauthorized)
				return
			}

			if !authentication.Authenticated() {
				log.Info(r.Context(), "Authentication failed, the request is unauthenticated")
				resource.WriteError(w, exception.Unauthorized)
				return
			}

			restrictedAuthorities := utils.ConvertRolesToSimpleAuthorities(protectedUrl.Roles)
			if err := accessDecisionManager.Decide(authentication, restrictedAuthorities); err != nil {
				if _, ok := err.(exception.Exception); ok {
					log.Info(r.Context(), "Authorization failed, error [%s]", err.Error())
				} else {
					log.Error(r.Context(), "Error when trying to authorize request, error [%v]", err)
				}
				resource.WriteError(w, err)
				return
			}

			// Continues to the next step
			next.ServeHTTP(w, r.WithContext(
				context.WithValue(r.Context(), constant.ContextAuthentication, authentication),
			))
		})
	}
}
