package client

import (
	"fmt"
	"gitlab.id.vin/vincart/golib/config"
	"regexp"
)

func NewSecurityProperties(loader config.Loader) (*SecurityProperties, error) {
	props := SecurityProperties{}
	err := loader.Bind(&props)
	return &props, err
}

type SecurityProperties struct {
	BasicAuth []*BasicAuthProperties
}

func (h SecurityProperties) Prefix() string {
	return "vinid.security.http.client"
}

func (h *SecurityProperties) PostBinding() error {
	for _, basicAuth := range h.BasicAuth {
		urlRegexp, err := regexp.Compile(basicAuth.UrlMatch)
		if err != nil {
			return fmt.Errorf("basic auth urlMatch [%s] is not valid in regex format with error [%v]",
				basicAuth.UrlMatch, err)
		}
		basicAuth.urlRegexp = urlRegexp
	}
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
