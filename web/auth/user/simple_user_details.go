package user

import (
	"github.com/golibs-starter/golib-security/web/auth/authorization/authority"
)

type SimpleUserDetails struct {
	userId      string
	authorities []authority.GrantedAuthority
}

func NewSimpleUserDetails(userId string, authorities []authority.GrantedAuthority) *SimpleUserDetails {
	return &SimpleUserDetails{userId: userId, authorities: authorities}
}

func (v SimpleUserDetails) Username() string {
	return v.userId
}

func (v SimpleUserDetails) Password() string {
	return ""
}

func (v SimpleUserDetails) Authorities() []authority.GrantedAuthority {
	return v.authorities
}
