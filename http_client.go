package golibsec

import (
	secHttpClient "gitlab.id.vin/vincart/golib-security/web/client"
	"gitlab.id.vin/vincart/golib/web/client"
)

func SecuredHttpClientWrapper() func(httpClient client.HttpClient) client.HttpClient {
	return func(httpClient client.HttpClient) client.HttpClient {
		return secHttpClient.NewSecuredHttpClient(httpClient)
	}
}
