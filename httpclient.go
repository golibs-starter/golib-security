package golibsec

import (
	secHttpClient "gitlab.id.vin/vincart/golib-security/web/client"
	"gitlab.id.vin/vincart/golib/web/client"
)

func SecuredHttpClientWrapper() func(client client.ContextualHttpClient) client.ContextualHttpClient {
	return func(client client.ContextualHttpClient) client.ContextualHttpClient {
		return secHttpClient.NewSecuredHttpClient(client)
	}
}
