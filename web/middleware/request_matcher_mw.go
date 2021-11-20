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
			if !strings.HasPrefix(r.URL.RequestURI(), contextPath) {
				log.Debug(r.Context(), "Forbidden, uri is not in context path")
				response.WriteError(w, exception.Forbidden)
				return
			}
			uri := removeContextPath(r.URL.RequestURI(), contextPath)
			if protectedUrl := getRequestMatched(r.Method, uri, properties.ProtectedUrls); protectedUrl != nil {
				log.Debug(r.Context(), "Matched protection URL pattern [%s], method [%s], roles [%v]",
					protectedUrl.UrlPattern, protectedUrl.Method, protectedUrl.Roles)
				next.ServeHTTP(w, secContext.AttachMatchedUrlProtection(r, protectedUrl))
				return
			}
			if matchesPublicRequest(uri, properties.PublicUrls) {
				log.Debug(r.Context(), "Url is in configured public url, skip")
				next.ServeHTTP(w, r)
				return
			}
			log.Debug(r.Context(), "Forbidden, url is not found in security config")
			response.WriteError(w, exception.Forbidden)
		})
	}
}

func getRequestMatched(method string, uri string, protectedUrls []*config.UrlToRole) *config.UrlToRole {
	if len(protectedUrls) > 0 {
		for _, protectedUrl := range protectedUrls {
			if protectedUrl.Method != "" && protectedUrl.Method != method {
				continue
			}
			if protectedUrl.UrlRegexp() != nil && protectedUrl.UrlRegexp().MatchString(uri) {
				return protectedUrl
			}
		}
	}
	return nil
}

func matchesPublicRequest(uri string, configuredPublicUrls []string) bool {
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
