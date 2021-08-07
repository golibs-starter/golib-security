package golibsec

import (
	"gitlab.id.vin/vincart/golib"
	"gitlab.id.vin/vincart/golib-security/web/auth/authen"
	"gitlab.id.vin/vincart/golib-security/web/auth/authorization"
	"gitlab.id.vin/vincart/golib-security/web/config"
	"gitlab.id.vin/vincart/golib-security/web/filter"
	"gitlab.id.vin/vincart/golib-security/web/middleware"
	coreConfig "gitlab.id.vin/vincart/golib/config"
)

type AuthFilterFn func(*config.HttpSecurityProperties, *authen.ProviderManager) filter.AuthenticationFilter
type AuthFilterFns []AuthFilterFn

func NewAuthFilterFns(fns ...AuthFilterFn) AuthFilterFns {
	return fns
}

func NewHttpSecurityAutoConfig(loader coreConfig.Loader) (*config.HttpSecurityProperties, error) {
	return config.NewHttpSecurityProperties(loader)
}

func RegisterHttpSecurityAutoConfig(app *golib.App, props *config.HttpSecurityProperties, authFilterFns AuthFilterFns) {
	authProviderManager := authen.NewProviderManager()
	accessDecisionManager := authorization.NewAffirmativeBasedADM(authorization.NewRoleVoterADV())
	filters := make([]filter.AuthenticationFilter, 0)
	for _, authFilterFn := range authFilterFns {
		filters = append(filters, authFilterFn(props, authProviderManager))
	}
	app.AddHandler(
		middleware.RequestMatcher(props, app.Path()),
		middleware.Auth(authProviderManager, accessDecisionManager, filters),
		middleware.SecurityContext(),
	)
}
