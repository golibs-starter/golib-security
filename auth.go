package golibsec

import (
	"fmt"
	"gitlab.id.vin/vincart/golib"
	"gitlab.id.vin/vincart/golib-security/web/config"
	"gitlab.id.vin/vincart/golib-security/web/filter"
	"gitlab.id.vin/vincart/golib-security/web/middleware"
)

type AuthFilter func(*config.HttpSecurityProperties) filter.SecurityFilter

func WithJwtAuth() AuthFilter {
	return func(properties *config.HttpSecurityProperties) filter.SecurityFilter {
		jwtFilter, err := filter.JwtSecurityFilter(properties)
		if err != nil {
			panic(fmt.Sprintf("Cannot init JWT Security Filter: [%v]", err))
		}
		return jwtFilter
	}
}

func WithAuthFilter(httpSecurityFilters ...AuthFilter) golib.Module {
	return func(app *golib.App) {
		properties := &config.HttpSecurityProperties{}
		app.ConfigLoader.Bind(properties)
		filters := make([]filter.SecurityFilter, 0)
		for _, httpSecFilter := range httpSecurityFilters {
			filters = append(filters, httpSecFilter(properties))
		}
		app.AddMiddleware(middleware.AuthFilterChain(properties, filters...))
	}
}
