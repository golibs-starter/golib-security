package middleware

import (
	"context"
	"gitlab.id.vin/vincart/golib-security/web/config"
	"gitlab.id.vin/vincart/golib-security/web/constant"
	"gitlab.id.vin/vincart/golib/exception"
	"gitlab.id.vin/vincart/golib/utils"
	"gitlab.id.vin/vincart/golib/web/log"
	"gitlab.id.vin/vincart/golib/web/resource"
	"net/http"
)

func RequestMatcher(properties *config.HttpSecurityProperties) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if matchesPublicRequest(r, append(properties.PredefinedPublicUrls, properties.PublicUrls...)) {
				log.Debug(r.Context(), "Url is in configured public url, skip")
				next.ServeHTTP(w, r)
				return
			}
			protectedUrl := getRequestMatched(r, properties.ProtectedUrls)
			if protectedUrl == nil {
				log.Debug(r.Context(), "Forbidden, no protected url matched")
				resource.WriteError(w, exception.Forbidden)
				return
			}
			log.Debug(r.Context(), "Protected URL is detected. URL pattern [%s], method [%s], roles [%v]",
				protectedUrl.UrlPattern, protectedUrl.Method, protectedUrl.Roles)
			next.ServeHTTP(w, r.WithContext(
				context.WithValue(r.Context(), constant.ContextProtectedUrl, protectedUrl),
			))
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

func matchesPublicRequest(r *http.Request, configuredPublicUrls []string) bool {
	return utils.ContainsString(configuredPublicUrls, r.URL.RequestURI())
}

func isProtectedRequest(r *http.Request) (protectedUrl *config.UrlToRole, protected bool) {
	protectedUrlVal := r.Context().Value(constant.ContextProtectedUrl)
	if protectedUrlVal == nil {
		return nil, false
	}
	return protectedUrlVal.(*config.UrlToRole), true
}
