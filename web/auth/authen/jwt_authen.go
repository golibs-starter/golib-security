package authen

import (
	"gitlab.id.vin/vincart/golib-security/web/auth/authorization/authority"
	"gitlab.id.vin/vincart/golib-security/web/auth/user"
)

type JwtTokenAuthentication struct {
	*BaseAuthentication
}

func NewJwtTokenAuthentication(userDetails user.Details, authorities []authority.GrantedAuthority) *JwtTokenAuthentication {
	base := NewBaseAuthentication(authorities)
	base.SetUserDetails(userDetails)
	return &JwtTokenAuthentication{base}
}
