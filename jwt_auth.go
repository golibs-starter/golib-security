package golibsec

import (
	"fmt"
	"gitlab.id.vin/vincart/golib-security/web/auth/authen"
	"gitlab.id.vin/vincart/golib-security/web/config"
	"gitlab.id.vin/vincart/golib-security/web/filter"
)

func UsingJwtAuth() AuthFilter {
	return func(props *config.HttpSecurityProperties, authPrm *authen.ProviderManager) filter.AuthenticationFilter {
		if props.Jwt == nil {
			panic("Missing JWT Auth config")
		}
		authPrm.AddProvider(authen.NewJwtAuthProvider())
		jwtFilter, err := filter.JwtAuthSecurityFilter(props.Jwt)
		if err != nil {
			panic(fmt.Sprintf("Cannot init JWT Security Filter: [%v]", err))
		}
		return jwtFilter
	}
}
