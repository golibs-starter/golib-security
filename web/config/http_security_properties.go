package config

import (
	"fmt"
	"gitlab.id.vin/vincart/golib-security/web/auth/authorization"
	"gitlab.id.vin/vincart/golib/config"
	"regexp"
	"strings"
)

func NewHttpSecurityProperties(loader config.Loader) (*HttpSecurityProperties, error) {
	props := HttpSecurityProperties{}
	err := loader.Bind(&props)
	return &props, err
}

type HttpSecurityProperties struct {
	PredefinedPublicUrls []string
	PublicUrls           []string
	ProtectedUrls        []*UrlToRole
	BasicAuth            *BasicSecurityProperties `default:"{}"`
	Jwt                  *JwtSecurityProperties   `default:"{}"`
}

func (h HttpSecurityProperties) Prefix() string {
	return "vinid.security.http"
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

	// Replace placeholder from environment for basic auth user
	if h.BasicAuth != nil && h.BasicAuth.Users != nil {
		for _, user := range h.BasicAuth.Users {
			if err := h.replacePlaceholderBasicAuthUser(user); err != nil {
				return fmt.Errorf("cannot replace placeholder for basic auth, error [%v]", err)
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

func (h HttpSecurityProperties) replacePlaceholderBasicAuthUser(user *BasicAuthProperties) error {
	newUsername, err := config.ReplacePlaceholderValue(user.Username)
	if err != nil {
		return fmt.Errorf("replace placeholder for username error [%v]", err)
	}
	user.Username = newUsername.(string)

	newPassword, err := config.ReplacePlaceholderValue(user.Password)
	if err != nil {
		return fmt.Errorf("replace placeholder for password error [%v]", err)
	}
	user.Password = newPassword.(string)
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
