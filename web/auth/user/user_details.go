package user

import (
	"gitlab.id.vin/vincart/golib-security/web/auth/authorization/authority"
)

type Details interface {
	Username() string
	Authorities() []authority.GrantedAuthority
}
