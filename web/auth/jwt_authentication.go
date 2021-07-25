package auth

import "gitlab.id.vin/vincart/golib-security/web/entity"

type JwtAuthentication struct {
	userDetails   entity.UserDetails
	authenticated bool
}

func NewJwtAuthentication(userDetails entity.UserDetails, authenticated bool) *JwtAuthentication {
	return &JwtAuthentication{userDetails: userDetails, authenticated: authenticated}
}

func (j JwtAuthentication) GetPrincipal() string {
	return j.userDetails.GetUserId()
}

func (j JwtAuthentication) GetDetails() entity.UserDetails {
	return j.userDetails
}

func (j JwtAuthentication) GetCredentials() interface{} {
	return nil
}

func (j JwtAuthentication) IsAuthenticated() bool {
	return j.authenticated
}
