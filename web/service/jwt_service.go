package service

import (
	"github.com/dgrijalva/jwt-go"
	"gitlab.com/golibs-starter/golib-security/web/auth/authen"
	"net/http"
)

type JwtService interface {
	GetAuthentication(token *jwt.Token, request *http.Request) (authen.Authentication, error)
}
