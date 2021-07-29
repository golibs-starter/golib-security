package authen

// AuthenticationManager Processes an Authentication request.
type AuthenticationManager interface {

	// Authenticate Attempts to authenticate the passed Authentication object,
	// returning a fully populated Authentication object (including granted authorities)if successful.
	Authenticate(authentication Authentication) (Authentication, error)
}
