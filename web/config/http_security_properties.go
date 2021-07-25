package config

import (
	"gitlab.id.vin/vincart/golib/log"
	"regexp"
)

type HttpSecurityProperties struct {
	PredefinedPublicUrls []string
	PublicUrls           []string
	ProtectedUrls        []*UrlToRole
	BasicAuth            BasicSecurityProperties
	Jwt                  JwtSecurityProperties
}

func (h HttpSecurityProperties) Prefix() string {
	return "vinid.security.http"
}

func (h *HttpSecurityProperties) PostBinding() {
	if len(h.ProtectedUrls) == 0 {
		return
	}
	for _, protectedUrl := range h.ProtectedUrls {
		urlRegexp, err := regexp.Compile(protectedUrl.UrlPattern)
		if err != nil {
			log.Warnf("Protected urlPattern [%s] is not valid in regex format with error [%v]",
				protectedUrl.UrlPattern, err)
			continue
		}
		protectedUrl.urlRegexp = urlRegexp
	}
}

type UrlToRole struct {
	Method                             string
	UrlPattern                         string
	Roles                              []string
	UnauthorizedWwwAuthenticateHeaders []string
	urlRegexp                          *regexp.Regexp
}

func (u UrlToRole) UrlRegexp() *regexp.Regexp {
	return u.urlRegexp
}
