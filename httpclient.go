package golibsec

import (
	"gitlab.id.vin/vincart/golib"
	secHttpClient "gitlab.id.vin/vincart/golib-security/web/client"
	"gitlab.id.vin/vincart/golib/web/client"
	"go.uber.org/fx"
)

func SecuredHttpClientOpt() fx.Option {
	return fx.Options(
		golib.EnablePropsAutoload(new(secHttpClient.SecurityProperties)),
		fx.Provide(secHttpClient.NewSecurityProperties),
		fx.Provide(fx.Annotated{
			Group:  "contextual_http_client_wrapper",
			Target: NewSecuredHttpClient,
		}),
	)
}

func NewSecuredHttpClient(props *secHttpClient.SecurityProperties) golib.ContextualHttpClientWrapper {
	return func(client client.ContextualHttpClient) (client.ContextualHttpClient, error) {
		return secHttpClient.NewSecuredHttpClient(client, props), nil
	}
}
