package user

import (
	"gitlab.id.vin/vincart/golib-security/web/auth/authorization/authority"
)

type VinIdUserDetails struct {
	userId      string
	authorities []authority.GrantedAuthority
}

func NewVinIdUserDetails(userId string, authorities []authority.GrantedAuthority) *VinIdUserDetails {
	return &VinIdUserDetails{userId: userId, authorities: authorities}
}

func (v VinIdUserDetails) Username() string {
	return v.userId
}

func (v VinIdUserDetails) Password() string {
	return ""
}

func (v VinIdUserDetails) Authorities() []authority.GrantedAuthority {
	return v.authorities
}
