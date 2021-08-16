package middleware

import (
	"gitlab.id.vin/vincart/golib-security/web/config"
	secContext "gitlab.id.vin/vincart/golib-security/web/context"
	"gitlab.id.vin/vincart/golib/exception"
	"gitlab.id.vin/vincart/golib/web/log"
	"gitlab.id.vin/vincart/golib/web/response"
	"net/http"
	"strings"
)

func RequestMatcher(properties *config.HttpSecurityProperties, contextPath string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			protectedUrl := getRequestMatched(contextPath, r, properties.ProtectedUrls)
			if protectedUrl == nil {
				publicUrls := append(properties.PredefinedPublicUrls, properties.PublicUrls...)
				if matchesPublicRequest(contextPath, r, publicUrls) {
					log.Debug(r.Context(), "Url is in configured public url, skip")
					next.ServeHTTP(w, r)
					return
				}
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
	return containsOrStartsString(configuredPublicUrls, uri)
}

func containsOrStartsString(slice []string, needle string) bool {
	for _, v := range slice {
		if needle == v {
			return true
		}
		length := len(v)
		if length > 0 && v[length-1:length] == "*" && strings.HasPrefix(needle, v[0:length-1]) {
			return true
		}
	}
	return false
}

func removeContextPath(uri string, contextPath string) string {
	uri = strings.TrimPrefix(uri, contextPath)
	return "/" + strings.TrimLeft(uri, "/")
}
