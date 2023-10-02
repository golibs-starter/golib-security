package user

import (
	"github.com/golibs-starter/golib-security/web/auth/authorization/authority"
)

type BasicUserDetails struct {
	username    string
	password    string
	authorities []authority.GrantedAuthority
}

func NewBasicUserDetails(
	username string,
	password string,
	authorities []authority.GrantedAuthority,
) *BasicUserDetails {
	return &BasicUserDetails{
		username:    username,
		password:    password,
		authorities: authorities,
	}
}

func (s BasicUserDetails) Username() string {
	return s.username
}

func (s BasicUserDetails) Password() string {
	return s.password
}

func (s BasicUserDetails) Authorities() []authority.GrantedAuthority {
	return s.authorities
}
