package filter

import (
	"gitlab.id.vin/vincart/golib-security/web/auth/authen"
	"gitlab.id.vin/vincart/golib-security/web/config"
	"net/http"
)

func BasicAuthSecurityFilter(properties *config.HttpSecurityProperties) (SecurityFilter, error) {
	return func(next SecurityHandler) SecurityHandler {
		return func(w http.ResponseWriter, r *http.Request) authen.Authentication {
			return nil
		}
	}, nil
}
