package golibsec

import (
	"github.com/golibs-starter/golib"
	secHttpClient "github.com/golibs-starter/golib-security/web/client"
	"github.com/golibs-starter/golib/web/client"
	"go.uber.org/fx"
)

func SecuredHttpClientOpt() fx.Option {
	return fx.Options(
		golib.ProvideProps(secHttpClient.NewSecurityProperties),
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
