package authorization

import (
	"gitlab.id.vin/vincart/golib-security/web/auth/authen"
	"gitlab.id.vin/vincart/golib-security/web/auth/authorization/authority"
)

type AffirmativeBasedADM struct {
	voters []AccessDecisionVoter
}

func NewAffirmativeBasedADM(voters ...AccessDecisionVoter) *AffirmativeBasedADM {
	return &AffirmativeBasedADM{voters: voters}
}

func (a AffirmativeBasedADM) Supports(authority authority.GrantedAuthority) bool {
	for _, voter := range a.voters {
		if voter.Supports(authority) {
			return true
		}
	}
	return false
}

func (a AffirmativeBasedADM) Decide(authentication authen.Authentication, restrictedAuthorities []authority.GrantedAuthority) error {
	for _, voter := range a.voters {
		if voter.Vote(authentication, restrictedAuthorities) == VotingGranted {
			return nil
		}
	}
	return AccessDenied
}
