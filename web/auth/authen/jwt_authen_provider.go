package authen

type JwtAuthProvider struct {
}

func NewJwtAuthProvider() *JwtAuthProvider {
	return &JwtAuthProvider{}
}

func (j JwtAuthProvider) Authenticate(authentication Authentication) (Authentication, error) {
	jwtAuth, _ := authentication.(*JwtAuthentication)
	jwtAuth.authenticated = true
	jwtAuth.authorities = jwtAuth.userDetails.Authorities()
	return jwtAuth, nil
}

func (j JwtAuthProvider) Supports(authentication Authentication) bool {
	_, ok := authentication.(*JwtAuthentication)
	return ok
}
