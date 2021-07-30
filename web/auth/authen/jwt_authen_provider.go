package authen

type JwtAuthProvider struct {
}

func NewJwtAuthProvider() *JwtAuthProvider {
	return &JwtAuthProvider{}
}

func (j JwtAuthProvider) Authenticate(authentication Authentication) (Authentication, error) {
	jwtAuth, _ := authentication.(*JwtTokenAuthentication)
	jwtAuth.authenticated = true
	return jwtAuth, nil
}

func (j JwtAuthProvider) Supports(authentication Authentication) bool {
	_, ok := authentication.(*JwtTokenAuthentication)
	return ok
}
