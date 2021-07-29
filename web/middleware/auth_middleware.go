package middleware

import (
	"gitlab.id.vin/vincart/golib-security/web/auth/authen"
	"gitlab.id.vin/vincart/golib-security/web/auth/authorization"
	"gitlab.id.vin/vincart/golib-security/web/auth/authorization/authority"
	"gitlab.id.vin/vincart/golib-security/web/config"
	"gitlab.id.vin/vincart/golib-security/web/filter"
	"gitlab.id.vin/vincart/golib/exception"
	"gitlab.id.vin/vincart/golib/web/log"
	"gitlab.id.vin/vincart/golib/web/resource"
	"net/http"
)

func AuthFilterChain(
	properties *config.HttpSecurityProperties,
	authenticationManager authen.AuthenticationManager,
	accessDecisionManager authorization.AccessDecisionManager,
	filters []filter.SecurityFilter,
) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			matchedUrl := getRequestMatched(r, properties.ProtectedUrls)
			if matchedUrl == nil {
				log.Info(r.Context(), "Forbidden, no protected url matched")
				resource.WriteError(w, exception.Forbidden)
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

			authentication, err := authenticationManager.Authenticate(authentication)
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

			restrictedAuthorities := convertRolesToSimpleAuthorities(matchedUrl.Roles)
			if err = accessDecisionManager.Decide(authentication, restrictedAuthorities); err != nil {
				if _, ok := err.(exception.Exception); ok {
					log.Info(r.Context(), "Authorization failed, error [%s]", err.Error())
				} else {
					log.Error(r.Context(), "Error when trying to authorize request, error [%v]", err)
				}
				resource.WriteError(w, err)
				return
			}

			// Continues to the next step if request is authorized
			next.ServeHTTP(w, r)
		})
	}
}

func getRequestMatched(r *http.Request, protectedUrls []*config.UrlToRole) *config.UrlToRole {
	if len(protectedUrls) > 0 {
		uri := r.URL.RequestURI()
		for _, protectedUrl := range protectedUrls {
			if protectedUrl.Method != "" && protectedUrl.Method != r.Method {
				continue
			}
			if protectedUrl.UrlRegexp() != nil && protectedUrl.UrlRegexp().MatchString(uri) {
				return protectedUrl
			}
		}
	}
	return nil
}

func convertRolesToSimpleAuthorities(roles []string) []authority.GrantedAuthority {
	authorities := make([]authority.GrantedAuthority, 0)
	for _, role := range roles {
		authorities = append(authorities, authority.NewSimpleGrantedAuthority(authorization.RolePrefix+role))
	}
	return authorities
}
