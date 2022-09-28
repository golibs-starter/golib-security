package service

import (
	"github.com/golang-jwt/jwt/v4"
	"gitlab.com/golibs-starter/golib-security/web/auth/authen"
	"net/http"
)

type JwtService interface {
	GetAuthentication(token *jwt.Token, request *http.Request) (authen.Authentication, error)
}
