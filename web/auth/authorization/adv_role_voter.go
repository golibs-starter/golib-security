package authorization

import (
	"gitlab.id.vin/vincart/golib-security/web/auth/authen"
	"gitlab.id.vin/vincart/golib-security/web/auth/authorization/authority"
	"gitlab.id.vin/vincart/golib/utils"
	"strings"
)

type RoleVoterADV struct {
}

func NewRoleVoterADV() *RoleVoterADV {
	return &RoleVoterADV{}
}

func (r RoleVoterADV) Supports(authority authority.GrantedAuthority) bool {
	return strings.HasPrefix(authority.Authority(), r.getRolePrefix())
}

func (r RoleVoterADV) Vote(auth authen.Authentication, restrictedAuthorities []authority.GrantedAuthority) VotingResult {
	if auth == nil {
		return AccessDenied
	}
	if restrictedAuthorities == nil || len(restrictedAuthorities) == 0 {
		return AccessGranted
	}
	grantedAuthorities := make([]string, 0)
	for _, grantedAuthority := range auth.Authorities() {
		grantedAuthorities = append(grantedAuthorities, grantedAuthority.Authority())
	}
	result := AccessAbstain
	for _, restrictedAuthority := range restrictedAuthorities {
		if r.Supports(restrictedAuthority) {
			result = AccessDenied
			if utils.ContainsString(grantedAuthorities, restrictedAuthority.Authority()) {
				return AccessGranted
			}
		}
	}
	return result
}

func (r RoleVoterADV) getRolePrefix() string {
	return "ROLE_"
}
