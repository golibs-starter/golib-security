package authen

import (
	"gitlab.id.vin/vincart/golib-security/web/auth/authorization/authority"
	"gitlab.id.vin/vincart/golib-security/web/auth/user"
)

type BaseAuthenticationToken struct {
	userDetails   user.Details
	authorities   []authority.GrantedAuthority
	authenticated bool
}

func NewBaseAuthenticationToken(authorities []authority.GrantedAuthority) *BaseAuthenticationToken {
	return &BaseAuthenticationToken{authorities: authorities}
}

func (j JwtAuthentication) Principal() string {
	return j.userDetails.Username()
}

func (j JwtAuthentication) Details() user.Details {
	return j.userDetails
}

func (j JwtAuthentication) Credentials() interface{} {
	return nil
}

func (j JwtAuthentication) Authorities() []authority.GrantedAuthority {
	return j.authorities
}

func (j JwtAuthentication) Authenticated() bool {
	return j.authenticated
}

func (b *BaseAuthenticationToken) SetUserDetails(userDetails user.Details) {
	b.userDetails = userDetails
}

func (b *BaseAuthenticationToken) SetAuthenticated(authenticated bool) {
	b.authenticated = authenticated
}
