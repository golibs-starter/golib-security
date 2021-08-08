package golibsec

import (
	"gitlab.id.vin/vincart/golib"
	secHttpClient "gitlab.id.vin/vincart/golib-security/web/client"
	"gitlab.id.vin/vincart/golib/config"
	"gitlab.id.vin/vincart/golib/web/client"
	"go.uber.org/fx"
)

type NewSecuredHttpClientIn struct {
	fx.In
	ConfigLoader config.Loader
}

type NewSecuredHttpClientOut struct {
	fx.Out
	Wrapper golib.ContextualHttpClientWrapper `group:"contextual_http_client_wrapper"`
}

func NewSecuredHttpClient(in NewSecuredHttpClientIn) NewSecuredHttpClientOut {
	return NewSecuredHttpClientOut{
		Wrapper: func(client client.ContextualHttpClient) (client.ContextualHttpClient, error) {
			securityProps, err := secHttpClient.NewSecurityProperties(in.ConfigLoader)
			if err != nil {
				return nil, err
			}
			return secHttpClient.NewSecuredHttpClient(client, securityProps), nil
		},
	}
}
