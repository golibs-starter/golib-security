package golibsec

import (
	"github.com/pkg/errors"
	"gitlab.id.vin/vincart/golib"
	"gitlab.id.vin/vincart/golib-security/web/config"
	"gitlab.id.vin/vincart/golib-security/web/middleware"
)

func WithJwtAuthentication() golib.Module {
	return func(app *golib.App) {
		properties := &config.HttpSecurityProperties{}
		app.ConfigLoader.Bind(properties)
		jwtAuthMiddleware, err := middleware.JwtAuth(properties)
		if err != nil {
			panic(errors.WithMessagef(err, "Cannot init JwtAuth Middleware"))
		}
		app.AddMiddleware(jwtAuthMiddleware)
	}
}
