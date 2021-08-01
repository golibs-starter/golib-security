package golibsec

import (
	"gitlab.id.vin/vincart/golib"
	secHttpClient "gitlab.id.vin/vincart/golib-security/web/client"
	"gitlab.id.vin/vincart/golib/web/client"
)

func UsingSecuredHttpClient() func(app *golib.App, client client.ContextualHttpClient) client.ContextualHttpClient {
	return func(app *golib.App, client client.ContextualHttpClient) client.ContextualHttpClient {
		securityProps := &secHttpClient.SecurityProperties{}
		app.ConfigLoader.Bind(securityProps)
		return secHttpClient.NewSecuredHttpClient(client, securityProps)
	}
}
