package client

import (
	"gitlab.id.vin/vincart/golib/web/client"
	"net/http"
)

type SecuredHttpClient struct {
	httpClient client.HttpClient
}

func NewSecuredHttpClient(httpClient client.HttpClient) *SecuredHttpClient {
	return &SecuredHttpClient{httpClient: httpClient}
}

func (s *SecuredHttpClient) Get(url string, result interface{}, options ...client.RequestOption) (*client.HttpResponse, error) {
	return s.Request(http.MethodGet, url, nil, result, options...)
}

func (s *SecuredHttpClient) Post(url string, body interface{}, result interface{}, options ...client.RequestOption) (*client.HttpResponse, error) {
	return s.Request(http.MethodPost, url, body, result, options...)
}

func (s *SecuredHttpClient) Put(url string, body interface{}, result interface{}, options ...client.RequestOption) (*client.HttpResponse, error) {
	return s.Request(http.MethodPut, url, body, result, options...)
}

func (s *SecuredHttpClient) Patch(url string, body interface{}, result interface{}, options ...client.RequestOption) (*client.HttpResponse, error) {
	return s.Request(http.MethodPatch, url, body, result, options...)
}

func (s *SecuredHttpClient) Delete(url string, body interface{}, result interface{}, options ...client.RequestOption) (*client.HttpResponse, error) {
	return s.Request(http.MethodDelete, url, body, result, options...)
}

func (s *SecuredHttpClient) Request(method string, url string, body interface{}, result interface{}, options ...client.RequestOption) (*client.HttpResponse, error) {
	return s.httpClient.Request(method, url, body, result, options...)
}
