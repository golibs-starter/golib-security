package golibsec

import (
	secHttpClient "gitlab.id.vin/vincart/golib-security/web/client"
	"gitlab.id.vin/vincart/golib/config"
	"gitlab.id.vin/vincart/golib/web/client"
)

func UsingSecuredHttpClient(loader config.Loader) func(client client.ContextualHttpClient) client.ContextualHttpClient {
	return func(client client.ContextualHttpClient) client.ContextualHttpClient {
		securityProps := secHttpClient.NewSecurityProperties(loader)
		return secHttpClient.NewSecuredHttpClient(client, securityProps)
	}
}
