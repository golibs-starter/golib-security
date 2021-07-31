package user

import (
	"gitlab.id.vin/vincart/golib-security/web/auth/authorization/authority"
)

type SimpleUserDetails struct {
	username    string
	password    string
	authorities []authority.GrantedAuthority
}

func NewSimpleUserDetails(
	username string,
	password string,
	authorities []authority.GrantedAuthority,
) *SimpleUserDetails {
	return &SimpleUserDetails{
		username:    username,
		password:    password,
		authorities: authorities,
	}
}

func (s SimpleUserDetails) Username() string {
	return s.username
}

func (s SimpleUserDetails) Password() string {
	return s.password
}

func (s SimpleUserDetails) Authorities() []authority.GrantedAuthority {
	return s.authorities
}
