package authorization

import (
	"github.com/golibs-starter/golib-security/web/auth/authen"
	"github.com/golibs-starter/golib-security/web/auth/authorization/authority"
)

type AccessDecisionManager interface {

	// Supports Indicates whether this AccessDecisionManager is able
	// to process authorization requests presented with the passed authorization.GrantedAuthority
	Supports(authority authority.GrantedAuthority) bool

	// Decide Resolves an access control decision for the passed parameters.
	Decide(authentication authen.Authentication, restrictedAuthorities []authority.GrantedAuthority) error
}
