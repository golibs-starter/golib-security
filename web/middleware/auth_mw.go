package middleware

import (
	"gitlab.com/golibs-starter/golib-security/utils"
	"gitlab.com/golibs-starter/golib-security/web/auth/authen"
	"gitlab.com/golibs-starter/golib-security/web/auth/authorization"
	"gitlab.com/golibs-starter/golib-security/web/constant"
	secContext "gitlab.com/golibs-starter/golib-security/web/context"
	"gitlab.com/golibs-starter/golib-security/web/filter"
	"gitlab.com/golibs-starter/golib/exception"
	"gitlab.com/golibs-starter/golib/log"
	"gitlab.com/golibs-starter/golib/web/response"
	"net/http"
)

func Auth(
	authManager authen.AuthenticationManager,
	accessDecisionManager authorization.AccessDecisionManager,
	filters []filter.AuthenticationFilter,
) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			logger := log.WithCtx(r.Context())
			matchedUrl := secContext.GetMatchedUrlProtection(r)
			if matchedUrl == nil {
				logger.Debug("Authentication is not required for this request, skip")
				next.ServeHTTP(w, r)
				return
			}

			// Create and run the security filter chain
			filterChainHandler := filter.CreateAuthenticationHandler(filters, filter.UnauthorizedHandler)
			authentication := filterChainHandler(w, r)
			if authentication == nil {
				logger.Info("Authentication is required to access this resource")
				writeAuthenticationDirective(w, matchedUrl.UnauthorizedWwwAuthenticateHeaders)
				response.WriteError(w, exception.Unauthorized)
				return
			}

			authentication, err := authManager.Authenticate(authentication)
			if err != nil {
				logger.WithError(err).Info("Authentication failed")
				response.WriteError(w, exception.Unauthorized)
				return
			}

			if !authentication.Authenticated() {
				logger.Info("Authentication failed, the request is unauthenticated")
				response.WriteError(w, exception.Unauthorized)
				return
			}

			restrictedAuthorities := utils.ConvertRolesToSimpleAuthorities(matchedUrl.Roles)
			if err := accessDecisionManager.Decide(authentication, restrictedAuthorities); err != nil {
				if _, ok := err.(exception.Exception); ok {
					logger.WithError(err).Info("Authorization failed")
				} else {
					logger.WithError(err).Error("Error when trying to authorize request")
				}
				response.WriteError(w, err)
				return
			}

			// Continues to the next step
			next.ServeHTTP(w, secContext.AttachAuthentication(r, authentication))
		})
	}
}

func writeAuthenticationDirective(w http.ResponseWriter, unauthorizedWwwAuthenticateHeaders []string) {
	for _, val := range unauthorizedWwwAuthenticateHeaders {
		w.Header().Add(constant.HeaderWWWAuthenticate, val)
	}
}
