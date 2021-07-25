package service

import (
	"github.com/dgrijalva/jwt-go"
	"gitlab.id.vin/vincart/golib-security/web/auth"
	"net/http"
)

type JwtService interface {
	GetAuthentication(token *jwt.Token, request *http.Request) (auth.Authentication, error)
}
