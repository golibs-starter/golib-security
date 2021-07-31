package authorization

type VotingResult int

const (
	VotingGranted VotingResult = 1
	VotingAbstain VotingResult = 0
	VotingDenied  VotingResult = -1
)

const RolePrefix = "ROLE_"
