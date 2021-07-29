package authen

type AuthenticationProvider interface {
	AuthenticationManager

	// Supports Returns true if this AuthenticationProvider supports the
	// indicated Authentication object.
	Supports(authentication Authentication) bool
}
