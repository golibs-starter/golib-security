package authen

import "errors"

type ProviderManager struct {
	providers []AuthenticationProvider
}

func NewProviderManager(providers ...AuthenticationProvider) *ProviderManager {
	return &ProviderManager{providers: providers}
}

func (p *ProviderManager) Authenticate(authentication Authentication) (Authentication, error) {
	for _, provider := range p.providers {
		if provider.Supports(authentication) {
			return provider.Authenticate(authentication)
		}
	}
	return nil, errors.New("authentication is not supported by any provided")
}

func (p *ProviderManager) AddProvider(provider AuthenticationProvider) {
	p.providers = append(p.providers, provider)
}
