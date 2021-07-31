package authen

import (
	"gitlab.id.vin/vincart/golib-security/web/auth/authorization/authority"
	"gitlab.id.vin/vincart/golib-security/web/auth/user"
)

type BaseAuthentication struct {
	userDetails   user.Details
	authorities   []authority.GrantedAuthority
	authenticated bool
}

func NewBaseAuthentication(authorities []authority.GrantedAuthority) *BaseAuthentication {
	if authorities == nil {
		authorities = make([]authority.GrantedAuthority, 0)
	}
	return &BaseAuthentication{authorities: authorities}
}

func (b BaseAuthentication) Details() user.Details {
	return b.userDetails
}

func (b BaseAuthentication) Authorities() []authority.GrantedAuthority {
	return b.authorities
}

func (b BaseAuthentication) Authenticated() bool {
	return b.authenticated
}

func (b *BaseAuthentication) SetUserDetails(userDetails user.Details) {
	b.userDetails = userDetails
}

func (b *BaseAuthentication) SetAuthenticated(authenticated bool) {
	b.authenticated = authenticated
}
