package authorization

import (
	"gitlab.id.vin/vincart/golib-security/web/auth/authen"
	"gitlab.id.vin/vincart/golib-security/web/auth/authorization/authority"
)

// AccessDecisionVoter Indicates a class is responsible
// for voting on authorization decisions.
// The coordination of voting is performed by an AccessDecisionManager
type AccessDecisionVoter interface {

	// Supports Indicates whether this AccessDecisionVoter
	// is able to vote on the passed GrantedAuthority
	Supports(authority authority.GrantedAuthority) bool

	// Vote Indicates whether access is granted or not.
	// The decision must be affirmative AccessGranted, negative AccessDenied
	// or the AccessDecisionVoter can abstain AccessAbstain from voting.
	Vote(authentication authen.Authentication, restrictedAuthorities []authority.GrantedAuthority) VotingResult
}

type VotingResult int

const (
	AccessGranted VotingResult = 1
	AccessAbstain VotingResult = 0
	AccessDenied  VotingResult = -1
)
