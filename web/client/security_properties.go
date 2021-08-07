package client

import (
	"fmt"
	"gitlab.id.vin/vincart/golib/config"
	"regexp"
)

type SecurityProperties struct {
	BasicAuth []*BasicAuthProperties
}

func NewSecurityProperties(loader config.Loader) *SecurityProperties {
	props := SecurityProperties{}
	loader.Bind(&props)
	return &props
}

func (h SecurityProperties) Prefix() string {
	return "vinid.security.http.client"
}

func (h *SecurityProperties) PostBinding() {
	for _, basicAuth := range h.BasicAuth {
		urlRegexp, err := regexp.Compile(basicAuth.UrlMatch)
		if err != nil {
			panic(fmt.Sprintf("Basic auth urlMatch [%s] is not valid in regex format with error [%v]",
				basicAuth.UrlMatch, err))
		}
		basicAuth.urlRegexp = urlRegexp

		if err := h.replacePlaceholderBasicAuthUser(basicAuth); err != nil {
			panic(fmt.Sprintf("Cannot replace placeholder for http client basic auth, error [%v]", err))
		}
	}
}

func (h SecurityProperties) replacePlaceholderBasicAuthUser(user *BasicAuthProperties) error {
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

type BasicAuthProperties struct {
	Username  string
	Password  string
	UrlMatch  string
	urlRegexp *regexp.Regexp
}

func (b BasicAuthProperties) UrlRegexp() *regexp.Regexp {
	return b.urlRegexp
}
