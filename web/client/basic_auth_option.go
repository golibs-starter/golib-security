package client

import (
	"context"
	"gitlab.id.vin/vincart/golib/web/client"
	"net/http"
)

func WithBasicAuthOption(ctx context.Context, basicAuths []*BasicAuthProperties) client.RequestOption {
	return func(r *http.Request) {
		url := r.URL.String()
		for _, auth := range basicAuths {
			if auth.UrlRegexp() == nil || !auth.urlRegexp.MatchString(url) {
				continue
			}
		}
	}
}
