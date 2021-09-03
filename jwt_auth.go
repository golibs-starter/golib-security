package golibsec

import (
	"errors"
	"fmt"
	"gitlab.id.vin/vincart/golib-security/web/auth/authen"
	"gitlab.id.vin/vincart/golib-security/web/config"
	"gitlab.id.vin/vincart/golib-security/web/filter"
	"go.uber.org/fx"
)

func JwtAuthFilterOpt() fx.Option {
	return fx.Provide(fx.Annotated{
		Group:  "authentication_filter",
		Target: NewJwtAuthFilter,
	})
}

type JwtAuthFilterIn struct {
	fx.In
	SecurityProperties  *config.HttpSecurityProperties
	AuthProviderManager *authen.ProviderManager
}

func NewJwtAuthFilter(in JwtAuthFilterIn) (filter.AuthenticationFilter, error) {
	if in.SecurityProperties.Jwt == nil {
		return nil, errors.New("missing JWT Auth config")
	}
	in.AuthProviderManager.AddProvider(authen.NewJwtAuthProvider())
	jwtFilter, err := filter.JwtAuthSecurityFilter(in.SecurityProperties.Jwt)
	if err != nil {
		return nil, fmt.Errorf("cannot init JWT Security Filter: [%v]", err)
	}
	return jwtFilter, nil
}
