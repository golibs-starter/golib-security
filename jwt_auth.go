package golibsec

import (
	"errors"
	"fmt"
	"gitlab.id.vin/vincart/golib-security/web/auth/authen"
	"gitlab.id.vin/vincart/golib-security/web/config"
	"gitlab.id.vin/vincart/golib-security/web/filter"
	"go.uber.org/fx"
)

type NewJwtAuthenticationFilterIn struct {
	fx.In
	SecurityProperties  *config.HttpSecurityProperties
	AuthProviderManager *authen.ProviderManager
}

type NewJwtAuthenticationFilterOut struct {
	fx.Out
	Filter filter.AuthenticationFilter `group:"authentication_filter"`
}

func NewJwtAuthenticationFilter(in NewJwtAuthenticationFilterIn) (NewJwtAuthenticationFilterOut, error) {
	out := NewJwtAuthenticationFilterOut{}
	if in.SecurityProperties.Jwt == nil {
		return out, errors.New("missing JWT Auth config")
	}
	in.AuthProviderManager.AddProvider(authen.NewJwtAuthProvider())
	jwtFilter, err := filter.JwtAuthSecurityFilter(in.SecurityProperties.Jwt)
	if err != nil {
		return NewJwtAuthenticationFilterOut{}, fmt.Errorf("cannot init JWT Security Filter: [%v]", err)
	}
	out.Filter = jwtFilter
	return out, nil
}
