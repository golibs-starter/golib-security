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
		log.Info("No protected urls have been defined")
		return
	}
	for _, protectedUrl := range h.ProtectedUrls {
		if err := h.validateRoles(protectedUrl.Roles); err != nil {
			panic(fmt.Sprintf("Roles is invalid, error [%s]", err.Error()))
		}
		if len(protectedUrl.UnauthorizedWwwAuthenticateHeaders) == 0 {
			panic(fmt.Sprintf("At least one WWW-Authenticate header values must be defined for pattern [%s]",
				protectedUrl.UrlPattern))
		}
		if regex, err := regexp.Compile(protectedUrl.UrlPattern); err != nil {
			log.Warnf("Url Pattern [%s] is not valid in regex format, error [%v]", protectedUrl.UrlPattern, err)
		} else {
			protectedUrl.urlRegexp = regex
		}
	}
}

func (h HttpSecurityProperties) validateRoles(roles []string) error {
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
