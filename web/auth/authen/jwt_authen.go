package authen

import (
	"gitlab.id.vin/vincart/golib-security/web/auth/authorization/authority"
	"gitlab.id.vin/vincart/golib-security/web/auth/user"
)

type JwtAuthentication struct {
	userDetails   user.Details
	authorities   []authority.GrantedAuthority
	authenticated bool
}

func NewJwtAuthentication(userDetails user.Details) *JwtAuthentication {
	return &JwtAuthentication{userDetails: userDetails}
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
