package golibsec

import (
	"errors"
	"gitlab.id.vin/vincart/golib"
	"gitlab.id.vin/vincart/golib-security/web/auth/authen"
	"gitlab.id.vin/vincart/golib-security/web/auth/authorization"
	"gitlab.id.vin/vincart/golib-security/web/config"
	"gitlab.id.vin/vincart/golib-security/web/filter"
	"gitlab.id.vin/vincart/golib-security/web/middleware"
	"go.uber.org/fx"
)

func HttpSecurityOpt() fx.Option {
	return fx.Options(
		golib.ProvideProps(config.NewHttpSecurityProperties),
		fx.Provide(NewHttpSecurity),
		fx.Invoke(RegisterHttpSecurity),
	)
}

type HttpSecurityOut struct {
	fx.Out
	AuthProviderManager   *authen.ProviderManager
	AccessDecisionManager authorization.AccessDecisionManager
}

func NewHttpSecurity() HttpSecurityOut {
	return HttpSecurityOut{
		AuthProviderManager:   authen.NewProviderManager(),
		AccessDecisionManager: authorization.NewAffirmativeBasedADM(authorization.NewRoleVoterADV()),
	}
}

type RegisterHttpSecurityIn struct {
	fx.In
	App                   *golib.App
	SecurityProperties    *config.HttpSecurityProperties
	AuthProviderManager   *authen.ProviderManager
	AccessDecisionManager authorization.AccessDecisionManager
	AuthenticationFilters []filter.AuthenticationFilter `group:"authentication_filter"`
}

func RegisterHttpSecurity(in RegisterHttpSecurityIn) error {
	if len(in.AuthenticationFilters) == 0 {
		return errors.New("no authentication filters are provided, please provide at least one")
	}
	in.App.AddHandler(
		middleware.RequestMatcher(in.SecurityProperties, in.App.Path()),
		middleware.Auth(in.AuthProviderManager, in.AccessDecisionManager, in.AuthenticationFilters),
		middleware.SecurityContext(),
	)
	return nil
}
