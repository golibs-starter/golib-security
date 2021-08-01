package middleware

import (
	"gitlab.id.vin/vincart/golib-security/web/auth/authen"
	"gitlab.id.vin/vincart/golib-security/web/auth/user"
	secContext "gitlab.id.vin/vincart/golib-security/web/context"
	"gitlab.id.vin/vincart/golib/web/context"
	"net/http"
)

func SecurityContext() func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authentication := secContext.GetAuthentication(r)
			if authentication != nil {
				setSecurityAttributes(r, authentication)
			}
			next.ServeHTTP(w, r)
		})
	}
}

func setSecurityAttributes(r *http.Request, authentication authen.Authentication) {
	userDetails := authentication.Details()
	requestAttributes := context.GetRequestAttributes(r.Context())
	if requestAttributes != nil {
		if u, ok := userDetails.(*user.VinIdUserDetails); ok {
			requestAttributes.SecurityAttributes.UserId = u.Username()
			return
		}
		requestAttributes.SecurityAttributes.TechnicalUsername = userDetails.Username()
	}
}