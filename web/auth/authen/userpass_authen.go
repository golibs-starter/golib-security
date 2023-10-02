package authen

import "github.com/golibs-starter/golib-security/web/auth/authorization/authority"

type UsernamePasswordAuthentication struct {
	*BaseAuthentication
	principal   interface{}
	credentials interface{}
}

func NewUsernamePasswordAuthentication(
	principal interface{},
	credentials interface{},
	authorities []authority.GrantedAuthority,
) *UsernamePasswordAuthentication {
	return &UsernamePasswordAuthentication{
		BaseAuthentication: NewBaseAuthentication(authorities),
		principal:          principal,
		credentials:        credentials,
	}
}

func (u *UsernamePasswordAuthentication) Principal() interface{} {
	return u.principal
}

func (u *UsernamePasswordAuthentication) Credentials() interface{} {
	return u.credentials
}

func (u *UsernamePasswordAuthentication) EraseCredentials() {
	u.credentials = nil
}
