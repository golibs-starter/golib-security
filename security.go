package golibsec

import (
	"fmt"
	"gitlab.id.vin/vincart/golib"
	"gitlab.id.vin/vincart/golib-security/web/auth/authen"
	"gitlab.id.vin/vincart/golib-security/web/auth/authorization"
	"gitlab.id.vin/vincart/golib-security/web/config"
	"gitlab.id.vin/vincart/golib-security/web/filter"
	"gitlab.id.vin/vincart/golib-security/web/middleware"
)

type AuthFilter func(*config.HttpSecurityProperties, *authen.ProviderManager) filter.SecurityFilter

func WithJwtAuth() AuthFilter {
	return func(properties *config.HttpSecurityProperties, authPrm *authen.ProviderManager) filter.SecurityFilter {
		authPrm.AddProvider(authen.NewJwtAuthProvider())
		jwtFilter, err := filter.JwtSecurityFilter(properties)
		if err != nil {
			panic(fmt.Sprintf("Cannot init JWT Security Filter: [%v]", err))
		}
		return jwtFilter
	}
}

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
		app.AddMiddleware(middleware.AuthFilterChain(
			properties,
			authProviderManager,
			accessDecisionManager,
			filters,
		))
	}
}
