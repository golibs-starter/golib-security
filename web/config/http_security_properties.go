package config

import (
	"fmt"
	"gitlab.id.vin/vincart/golib-security/web/auth/authorization"
	"gitlab.id.vin/vincart/golib/log"
	"regexp"
	"strings"
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
		if err := h.checkRolesValid(protectedUrl.Roles); err != nil {
			panic(fmt.Sprintf("Roles is invalid, error [%s]", err.Error()))
		}
		urlRegexp, err := regexp.Compile(protectedUrl.UrlPattern)
		if err != nil {
			log.Warnf("Protected urlPattern [%s] is not valid in regex format with error [%v]",
				protectedUrl.UrlPattern, err)
			continue
		}
		protectedUrl.urlRegexp = urlRegexp
	}
}

func (h HttpSecurityProperties) checkRolesValid(roles []string) error {
	for _, role := range roles {
		if strings.HasPrefix(role, authorization.RolePrefix) {
			return fmt.Errorf("role should not start with '%s' since it is automatically inserted, got %s",
				authorization.RolePrefix, role)
		}
	}
	return nil
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
