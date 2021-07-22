package service

type Authentication interface {
	GetCredentials() interface{}
	getDetails() interface{}
	IsAuthenticated() bool
}
