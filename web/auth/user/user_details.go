package user

import (
	"gitlab.id.vin/vincart/golib-security/web/auth/authorization/authority"
)

type Details interface {

	// Username Returns the username
	Username() string

	// Password Returns the user's password.
	Password() string

	// Authorities Returns the authorities granted to the user.
	Authorities() []authority.GrantedAuthority
}
