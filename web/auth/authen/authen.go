package authen

import (
	"github.com/golibs-starter/golib-security/web/auth/authorization/authority"
	"github.com/golibs-starter/golib-security/web/auth/user"
)

type Authentication interface {

	// Principal The identity of the principal being authenticated.
	// This might be a user id or username
	Principal() interface{}

	// Details Stores additional details about the authentication request.
	// These might contain username, a device id etc.
	Details() user.Details

	// Credentials The credentials that prove the principal is correct.
	// This is usually a password, token, api key or null if not used
	Credentials() interface{}

	// Authorities Indicates the authorities that the
	// principal has been granted
	Authorities() []authority.GrantedAuthority

	// Authenticated Indicates the request has been authenticated or not?
	// If not, we need to authenticate in the next step.
	Authenticated() bool
}
