package utils

import (
	"gitlab.com/golibs-starter/golib-security/web/auth/authorization"
	"gitlab.com/golibs-starter/golib-security/web/auth/authorization/authority"
)

func ConvertRolesToSimpleAuthorities(roles []string) []authority.GrantedAuthority {
	authorities := make([]authority.GrantedAuthority, 0)
	if roles == nil {
		return authorities
	}
	for _, role := range roles {
		authorities = append(authorities, authority.NewSimpleGrantedAuthority(authorization.RolePrefix+role))
	}
	return authorities
}
