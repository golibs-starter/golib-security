package authen

import (
	"github.com/dgrijalva/jwt-go"
	"gitlab.com/golibs-starter/golib-security/web/auth/authorization/authority"
	"gitlab.com/golibs-starter/golib-security/web/auth/user"
)

type JwtTokenAuthentication struct {
	*BaseAuthentication
	claims jwt.MapClaims
}

func NewJwtTokenAuthentication(
	userDetails user.Details,
	authorities []authority.GrantedAuthority,
	claims jwt.MapClaims,
) *JwtTokenAuthentication {
	base := NewBaseAuthentication(authorities)
	base.SetUserDetails(userDetails)
	return &JwtTokenAuthentication{BaseAuthentication: base, claims: claims}
}

func (j *JwtTokenAuthentication) Principal() interface{} {
	return j.userDetails.Username()
}

func (j *JwtTokenAuthentication) Credentials() interface{} {
	return nil
}

func (j JwtTokenAuthentication) Claims() jwt.MapClaims {
	return j.claims
}
