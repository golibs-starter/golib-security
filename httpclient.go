package golibsec

import (
	"gitlab.id.vin/vincart/golib"
	secHttpClient "gitlab.id.vin/vincart/golib-security/web/client"
	"gitlab.id.vin/vincart/golib/web/client"
	"go.uber.org/fx"
)

func SecuredHttpClientAutoConfig() fx.Option {
	return fx.Options(
		golib.EnablePropsAutoload(new(secHttpClient.SecurityProperties)),
		fx.Provide(secHttpClient.NewSecurityProperties),
		fx.Provide(NewSecuredHttpClient),
	)
}

type NewSecuredHttpClientOut struct {
	fx.Out
	Wrapper golib.ContextualHttpClientWrapper `group:"contextual_http_client_wrapper"`
}

func NewSecuredHttpClient(props *secHttpClient.SecurityProperties) NewSecuredHttpClientOut {
	return NewSecuredHttpClientOut{
		Wrapper: func(client client.ContextualHttpClient) (client.ContextualHttpClient, error) {
			return secHttpClient.NewSecuredHttpClient(client, props), nil
		},
	}
}
