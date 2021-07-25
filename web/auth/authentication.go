package auth

import "gitlab.id.vin/vincart/golib-security/web/entity"

type Authentication interface {

	// GetPrincipal The identity of the principal being authenticated.
	// This might be an user id or username
	GetPrincipal() string

	// GetDetails Stores additional details about the authentication request.
	// These might contains user name, an device id etc.
	GetDetails() entity.UserDetails

	// GetCredentials The credentials that prove the principal is correct.
	// This is usually a password, token, api key or null if not used
	GetCredentials() interface{}

	// IsAuthenticated Indicates the request has been authenticated or not?
	// If not, we need to authenticate in the next step.
	IsAuthenticated() bool
}
