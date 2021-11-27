package client

import (
	"context"
	"gitlab.com/golibs-starter/golib/web/client"
	"net/http"
)

type SecuredHttpClient struct {
	client     client.ContextualHttpClient
	properties *SecurityProperties
}

func NewSecuredHttpClient(
	client client.ContextualHttpClient,
	properties *SecurityProperties,
) *SecuredHttpClient {
	return &SecuredHttpClient{
		client:     client,
		properties: properties,
	}
}

func (s *SecuredHttpClient) Get(ctx context.Context, url string, result interface{},
	options ...client.RequestOption) (*client.HttpResponse, error) {
	return s.Request(ctx, http.MethodGet, url, nil, result, options...)
}

func (s *SecuredHttpClient) Post(ctx context.Context, url string, body interface{}, result interface{},
	options ...client.RequestOption) (*client.HttpResponse, error) {
	return s.Request(ctx, http.MethodPost, url, body, result, options...)
}

func (s *SecuredHttpClient) Put(ctx context.Context, url string, body interface{}, result interface{},
	options ...client.RequestOption) (*client.HttpResponse, error) {
	return s.Request(ctx, http.MethodPut, url, body, result, options...)
}

func (s *SecuredHttpClient) Patch(ctx context.Context, url string, body interface{}, result interface{},
	options ...client.RequestOption) (*client.HttpResponse, error) {
	return s.Request(ctx, http.MethodPatch, url, body, result, options...)
}

func (s *SecuredHttpClient) Delete(ctx context.Context, url string, body interface{}, result interface{},
	options ...client.RequestOption) (*client.HttpResponse, error) {
	return s.Request(ctx, http.MethodDelete, url, body, result, options...)
}

func (s *SecuredHttpClient) Request(ctx context.Context, method string, url string, body interface{},
	result interface{}, options ...client.RequestOption) (*client.HttpResponse, error) {
	httpOpts := make([]client.RequestOption, 0)
	for _, auth := range s.properties.BasicAuth {
		if auth.UrlRegexp() != nil && auth.UrlRegexp().MatchString(url) {
			httpOpts = append(httpOpts, client.WithBasicAuth(auth.Username, auth.Password))
		}
	}
	httpOpts = append(httpOpts, options...)
	return s.client.Request(ctx, method, url, body, result, httpOpts...)
}
