package golibsec

import (
	"errors"
	"gitlab.id.vin/vincart/golib"
	"gitlab.id.vin/vincart/golib-security/web/auth/authen"
	"gitlab.id.vin/vincart/golib-security/web/auth/authorization"
	"gitlab.id.vin/vincart/golib-security/web/config"
	"gitlab.id.vin/vincart/golib-security/web/filter"
	"gitlab.id.vin/vincart/golib-security/web/middleware"
	coreConfig "gitlab.id.vin/vincart/golib/config"
	"go.uber.org/fx"
)

type HttpSecurityAutoConfigIn struct {
	fx.In
	ConfigLoader coreConfig.Loader
}

type HttpSecurityAutoConfigOut struct {
	fx.Out
	SecurityProperties    *config.HttpSecurityProperties
	AuthProviderManager   *authen.ProviderManager
	AccessDecisionManager authorization.AccessDecisionManager
}

func NewHttpSecurityAutoConfig(in HttpSecurityAutoConfigIn) (HttpSecurityAutoConfigOut, error) {
	out := HttpSecurityAutoConfigOut{}
	props, err := config.NewHttpSecurityProperties(in.ConfigLoader)
	if err != nil {
		return out, err
	}
	out.SecurityProperties = props
	out.AuthProviderManager = authen.NewProviderManager()
	out.AccessDecisionManager = authorization.NewAffirmativeBasedADM(authorization.NewRoleVoterADV())
	return out, nil
}

type RegisterHttpSecurityAutoConfigIn struct {
	fx.In
	App                   *golib.App
	SecurityProperties    *config.HttpSecurityProperties
	AuthProviderManager   *authen.ProviderManager
	AccessDecisionManager authorization.AccessDecisionManager
	AuthenticationFilters []filter.AuthenticationFilter `group:"authentication_filter"`
}

func RegisterHttpSecurityAutoConfig(in RegisterHttpSecurityAutoConfigIn) error {
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
