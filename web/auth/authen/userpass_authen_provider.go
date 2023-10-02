package authen

import (
	"errors"
	"github.com/golibs-starter/golib-security/crypto"
	"github.com/golibs-starter/golib-security/web/auth/user"
)

type UsernamePasswordAuthProvider struct {
	userService     user.Service
	passwordEncoder crypto.PasswordEncoder
}

func NewUsernamePasswordAuthProvider(
	userService user.Service,
	passwordEncoder crypto.PasswordEncoder,
) *UsernamePasswordAuthProvider {
	return &UsernamePasswordAuthProvider{
		userService:     userService,
		passwordEncoder: passwordEncoder,
	}
}

func (j UsernamePasswordAuthProvider) Authenticate(authentication Authentication) (Authentication, error) {
	auth, ok := authentication.(*UsernamePasswordAuthentication)
	if !ok {
		return nil, errors.New("only UsernamePasswordAuthentication is supported")
	}
	username := auth.Principal().(string)
	userDetails, err := j.userService.GetByUsername(username)
	if err != nil {
		return nil, err
	}
	if err := j.checkCredentials(userDetails, auth); err != nil {
		return nil, err
	}
	authenticatedObject := NewUsernamePasswordAuthentication(
		authentication.Principal(),
		authentication.Credentials(),
		userDetails.Authorities(),
	)
	authenticatedObject.SetUserDetails(userDetails)
	authenticatedObject.SetAuthenticated(true)
	return authenticatedObject, nil
}

func (j UsernamePasswordAuthProvider) Supports(authentication Authentication) bool {
	_, ok := authentication.(*UsernamePasswordAuthentication)
	return ok
}

func (j UsernamePasswordAuthProvider) checkCredentials(userDetails user.Details, auth *UsernamePasswordAuthentication) error {
	if auth.Credentials() == nil {
		return BadCredentials
	}
	if !j.passwordEncoder.Matches(auth.Credentials().(string), userDetails.Password()) {
		return BadCredentials
	}
	return nil
}
