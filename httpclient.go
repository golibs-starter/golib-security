package golibsec

import (
	"gitlab.id.vin/vincart/golib"
	secHttpClient "gitlab.id.vin/vincart/golib-security/web/client"
	"gitlab.id.vin/vincart/golib/config"
	"gitlab.id.vin/vincart/golib/web/client"
)

func UsingSecuredHttpClient(loader config.Loader) golib.ContextualHttpClientWrapper {
	return func(client client.ContextualHttpClient) (client.ContextualHttpClient, error) {
		securityProps, err := secHttpClient.NewSecurityProperties(loader)
		if err != nil {
			return nil, err
		}
		return secHttpClient.NewSecuredHttpClient(client, securityProps), nil
	}
}
