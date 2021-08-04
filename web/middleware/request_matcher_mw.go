package middleware

import (
	"gitlab.id.vin/vincart/golib"
	"gitlab.id.vin/vincart/golib-security/web/config"
	secContext "gitlab.id.vin/vincart/golib-security/web/context"
	"gitlab.id.vin/vincart/golib/exception"
	"gitlab.id.vin/vincart/golib/utils"
	"gitlab.id.vin/vincart/golib/web/log"
	"gitlab.id.vin/vincart/golib/web/resource"
	"net/http"
	"strings"
)

func RequestMatcher(app *golib.App, properties *config.HttpSecurityProperties) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if matchesPublicRequest(app, r, append(properties.PredefinedPublicUrls, properties.PublicUrls...)) {
				log.Debug(r.Context(), "Url is in configured public url, skip")
				next.ServeHTTP(w, r)
				return
			}
			protectedUrl := getRequestMatched(app, r, properties.ProtectedUrls)
			if protectedUrl == nil {
				log.Debug(r.Context(), "Forbidden, no protected url matched")
				resource.WriteError(w, exception.Forbidden)
				return
			}
			log.Debug(r.Context(), "Matched protection URL pattern [%s], method [%s], roles [%v]",
				protectedUrl.UrlPattern, protectedUrl.Method, protectedUrl.Roles)
			next.ServeHTTP(w, secContext.AttachMatchedUrlProtection(r, protectedUrl))
		})
	}
}

func getRequestMatched(app *golib.App, r *http.Request, protectedUrls []*config.UrlToRole) *config.UrlToRole {
	if len(protectedUrls) > 0 {
		uri := removeContextPath(r.URL.RequestURI(), app.Path())
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

func matchesPublicRequest(app *golib.App, r *http.Request, configuredPublicUrls []string) bool {
	uri := removeContextPath(r.URL.RequestURI(), app.Path())
	return utils.ContainsString(configuredPublicUrls, uri)
}

func removeContextPath(uri string, contextPath string) string {
	uri = strings.TrimLeft(uri, contextPath)
	return "/" + strings.TrimLeft(uri, "/")
}
