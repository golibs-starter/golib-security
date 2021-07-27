package middleware

import (
	"context"
	"gitlab.id.vin/vincart/golib-security/web/config"
	"gitlab.id.vin/vincart/golib-security/web/constant"
	"gitlab.id.vin/vincart/golib-security/web/filter"
	"gitlab.id.vin/vincart/golib/exception"
	"gitlab.id.vin/vincart/golib/web/resource"
	"net/http"
)

func AuthFilterChain(properties *config.HttpSecurityProperties, filters ...filter.SecurityFilter) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			matchedUrl := getRequestMatched(r, properties.ProtectedUrls)
			if matchedUrl == nil {
				resource.WriteError(w, exception.Forbidden)
				return
			}
			r = r.WithContext(context.WithValue(r.Context(), constant.MatchedUrlContext, matchedUrl))

			// Create and run the security filter chain
			filter.CreateChainHandler(filters, filter.UnauthorizedHandler)(w, r)

			// Continues to the next step if request is authorized
			if r.Context().Value(constant.UnauthorizedContext) == nil {
				next.ServeHTTP(w, r)
			}
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
