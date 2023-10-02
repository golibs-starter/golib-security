package authorization

import (
	"github.com/golibs-starter/golib-security/web/auth/authen"
	"github.com/golibs-starter/golib-security/web/auth/authorization/authority"
	"github.com/golibs-starter/golib/utils"
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
		return VotingDenied
	}
	if restrictedAuthorities == nil || len(restrictedAuthorities) == 0 {
		return VotingGranted
	}
	grantedAuthorities := make([]string, 0)
	for _, grantedAuthority := range auth.Authorities() {
		grantedAuthorities = append(grantedAuthorities, grantedAuthority.Authority())
	}
	result := VotingAbstain
	for _, restrictedAuthority := range restrictedAuthorities {
		if r.Supports(restrictedAuthority) {
			result = VotingDenied
			if utils.ContainsString(grantedAuthorities, restrictedAuthority.Authority()) {
				return VotingGranted
			}
		}
	}
	return result
}

func (r RoleVoterADV) getRolePrefix() string {
	return "ROLE_"
}
