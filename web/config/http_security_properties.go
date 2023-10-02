package config

import (
	"fmt"
	"github.com/golibs-starter/golib-security/web/auth/authorization"
	"github.com/golibs-starter/golib/config"
	"regexp"
	"strings"
)

func NewHttpSecurityProperties(loader config.Loader) (*HttpSecurityProperties, error) {
	props := HttpSecurityProperties{}
	err := loader.Bind(&props)
	return &props, err
}

type HttpSecurityProperties struct {
	PublicUrls    []string
	ProtectedUrls []*UrlToRole
	BasicAuth     *BasicSecurityProperties `default:"{}"`
	Jwt           *JwtSecurityProperties   `default:"{}"`
}

func (h HttpSecurityProperties) Prefix() string {
	return "app.security.http"
}

func (h *HttpSecurityProperties) PostBinding() error {
	// Validate protected urls
	if len(h.ProtectedUrls) > 0 {
		for _, protectedUrl := range h.ProtectedUrls {
			if err := h.validateProtectedUrl(protectedUrl); err != nil {
				return fmt.Errorf("protected url is invalid, error [%s]", err.Error())
			}
		}
	}
	return nil
}

func (h HttpSecurityProperties) validateProtectedUrl(url *UrlToRole) error {
	if err := h.validateRoles(url.Roles); err != nil {
		return fmt.Errorf("roles is invalid, error [%s]", err.Error())
	}
	if len(url.UnauthorizedWwwAuthenticateHeaders) == 0 {
		return fmt.Errorf("at least one www-authenticate header values must be defined for pattern [%s]",
			url.UrlPattern)
	}
	regex, err := regexp.Compile(url.UrlPattern)
	if err != nil {
		return fmt.Errorf("url pattern [%s] is not valid in regex format, error [%v]", url.UrlPattern, err)
	}
	url.urlRegexp = regex
	return nil
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
