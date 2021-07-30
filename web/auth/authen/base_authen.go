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
	return &BaseAuthentication{authorities: authorities}
}

func (j JwtTokenAuthentication) Principal() string {
	return j.userDetails.Username()
}

func (j JwtTokenAuthentication) Details() user.Details {
	return j.userDetails
}

func (j JwtTokenAuthentication) Credentials() interface{} {
	return nil
}

func (j JwtTokenAuthentication) Authorities() []authority.GrantedAuthority {
	return j.authorities
}

func (j JwtTokenAuthentication) Authenticated() bool {
	return j.authenticated
}

func (b *BaseAuthentication) SetUserDetails(userDetails user.Details) {
	b.userDetails = userDetails
}

func (b *BaseAuthentication) SetAuthenticated(authenticated bool) {
	b.authenticated = authenticated
}
