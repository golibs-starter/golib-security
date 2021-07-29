package authen

// Manager Processes an Authentication request.
type Manager interface {

	// Authenticate Attempts to authenticate the passed Authentication object,
	// returning a fully populated Authentication object (including granted authorities)if successful.
	Authenticate(authentication Authentication) (Authentication, error)
}
