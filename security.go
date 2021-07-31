package golibsec

import (
	"gitlab.id.vin/vincart/golib"
	"gitlab.id.vin/vincart/golib-security/web/auth/authen"
	"gitlab.id.vin/vincart/golib-security/web/auth/authorization"
	"gitlab.id.vin/vincart/golib-security/web/config"
	"gitlab.id.vin/vincart/golib-security/web/filter"
	"gitlab.id.vin/vincart/golib-security/web/middleware"
)

type AuthFilter func(*config.HttpSecurityProperties, *authen.ProviderManager) filter.SecurityFilter

func WithHttpSecurityAutoConfig(httpSecurityFilters ...AuthFilter) golib.Module {
	return func(app *golib.App) {
		properties := &config.HttpSecurityProperties{}
		app.ConfigLoader.Bind(properties)
		authProviderManager := authen.NewProviderManager()
		accessDecisionManager := authorization.NewAffirmativeBasedADM(authorization.NewRoleVoterADV())
		filters := make([]filter.SecurityFilter, 0)
		for _, httpSecFilter := range httpSecurityFilters {
			filters = append(filters, httpSecFilter(properties, authProviderManager))
		}
		app.AddMiddleware(
			middleware.RequestMatcher(properties),
			middleware.Auth(authProviderManager, accessDecisionManager, filters),
		)
	}
}
