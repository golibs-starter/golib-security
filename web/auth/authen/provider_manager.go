package authen

import "errors"

type ProviderManager struct {
	providers []AuthenticationProvider
}

func NewProviderManager(providers ...AuthenticationProvider) *ProviderManager {
	return &ProviderManager{providers: providers}
}

func (p *ProviderManager) Authenticate(authentication Authentication) (result Authentication, err error) {
	for _, provider := range p.providers {
		if provider.Supports(authentication) {
			result, err = provider.Authenticate(authentication)
			break
		}
	}
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, errors.New("authentication is not supported by any provided")
	}
	if cc, ok := authentication.(CredentialsContainer); ok {
		cc.EraseCredentials()
	}
	if cc, ok := result.(CredentialsContainer); ok {
		cc.EraseCredentials()
	}
	return result, err
}

func (p *ProviderManager) AddProvider(provider AuthenticationProvider) {
	p.providers = append(p.providers, provider)
}
