package client

import (
	"context"
	"gitlab.id.vin/vincart/golib/web/client"
	"net/http"
)

type SecuredHttpClient struct {
	httpClient client.ContextualHttpClient
}

func NewSecuredHttpClient(client client.ContextualHttpClient) *SecuredHttpClient {
	return &SecuredHttpClient{httpClient: client}
}

func (s *SecuredHttpClient) Get(ctx context.Context, url string, result interface{}, options ...client.RequestOption) (*client.HttpResponse, error) {
	return s.Request(ctx, http.MethodGet, url, nil, result, options...)
}

func (s *SecuredHttpClient) Post(ctx context.Context, url string, body interface{}, result interface{}, options ...client.RequestOption) (*client.HttpResponse, error) {
	return s.Request(ctx, http.MethodPost, url, body, result, options...)
}

func (s *SecuredHttpClient) Put(ctx context.Context, url string, body interface{}, result interface{}, options ...client.RequestOption) (*client.HttpResponse, error) {
	return s.Request(ctx, http.MethodPut, url, body, result, options...)
}

func (s *SecuredHttpClient) Patch(ctx context.Context, url string, body interface{}, result interface{}, options ...client.RequestOption) (*client.HttpResponse, error) {
	return s.Request(ctx, http.MethodPatch, url, body, result, options...)
}

func (s *SecuredHttpClient) Delete(ctx context.Context, url string, body interface{}, result interface{}, options ...client.RequestOption) (*client.HttpResponse, error) {
	return s.Request(ctx, http.MethodDelete, url, body, result, options...)
}

func (s *SecuredHttpClient) Request(ctx context.Context, method string, url string, body interface{}, result interface{}, options ...client.RequestOption) (*client.HttpResponse, error) {
	return s.httpClient.Request(ctx, method, url, body, result, options...)
}
