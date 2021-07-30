package authen

import (
	"gitlab.id.vin/vincart/golib-security/web/auth/authorization/authority"
	"gitlab.id.vin/vincart/golib-security/web/auth/user"
)

type JwtAuthentication struct {
	*BaseAuthenticationToken
}

func NewJwtAuthentication(userDetails user.Details, authorities []authority.GrantedAuthority) *JwtAuthentication {
	base := NewBaseAuthenticationToken(authorities)
	base.SetUserDetails(userDetails)
	return &JwtAuthentication{base}
}
