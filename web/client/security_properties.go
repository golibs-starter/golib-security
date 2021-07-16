package client

import (
	"gitlab.id.vin/vincart/golib/log"
	"regexp"
)

type SecurityProperties struct {
	BasicAuth []*BasicAuthProperties `mapstructure:"basic_auth"`
}

func (h SecurityProperties) Prefix() string {
	return "vinid.security.http.client"
}

func (h *SecurityProperties) PostBinding() {
	for _, basicAuth := range h.BasicAuth {
		urlRegexp, err := regexp.Compile(basicAuth.UrlMatch)
		if err != nil {
			log.Warnf("Basic auth url_match [%s] is not valid in regex format with error [%v]",
				basicAuth.UrlMatch, err)
			continue
		}
		basicAuth.urlRegexp = urlRegexp
	}
}

type BasicAuthProperties struct {
	Username  string `mapstructure:"username"`
	Password  string `mapstructure:"password"`
	UrlMatch  string `mapstructure:"url_match"`
	urlRegexp *regexp.Regexp
}

func (b BasicAuthProperties) UrlRegexp() *regexp.Regexp {
	return b.urlRegexp
}
