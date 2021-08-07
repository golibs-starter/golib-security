package middleware

import (
	"gitlab.id.vin/vincart/golib-security/web/config"
	secContext "gitlab.id.vin/vincart/golib-security/web/context"
	"gitlab.id.vin/vincart/golib/exception"
	"gitlab.id.vin/vincart/golib/utils"
	"gitlab.id.vin/vincart/golib/web/log"
	"gitlab.id.vin/vincart/golib/web/response"
	"net/http"
	"strings"
)

func RequestMatcher(properties *config.HttpSecurityProperties, contextPath string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if matchesPublicRequest(contextPath, r, append(properties.PredefinedPublicUrls, properties.PublicUrls...)) {
				log.Debug(r.Context(), "Url is in configured public url, skip")
				next.ServeHTTP(w, r)
				return
			}
			protectedUrl := getRequestMatched(contextPath, r, properties.ProtectedUrls)
			if protectedUrl == nil {
				log.Debug(r.Context(), "Forbidden, no protected url matched")
				response.WriteError(w, exception.Forbidden)
				return
			}
			log.Debug(r.Context(), "Matched protection URL pattern [%s], method [%s], roles [%v]",
				protectedUrl.UrlPattern, protectedUrl.Method, protectedUrl.Roles)
			next.ServeHTTP(w, secContext.AttachMatchedUrlProtection(r, protectedUrl))
		})
	}
}

func getRequestMatched(contextPath string, r *http.Request, protectedUrls []*config.UrlToRole) *config.UrlToRole {
	if len(protectedUrls) > 0 {
		uri := removeContextPath(r.URL.RequestURI(), contextPath)
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

func matchesPublicRequest(contextPath string, r *http.Request, configuredPublicUrls []string) bool {
	uri := removeContextPath(r.URL.RequestURI(), contextPath)
	return utils.ContainsString(configuredPublicUrls, uri)
}

func removeContextPath(uri string, contextPath string) string {
	uri = strings.TrimPrefix(uri, contextPath)
	return "/" + strings.TrimLeft(uri, "/")
}
