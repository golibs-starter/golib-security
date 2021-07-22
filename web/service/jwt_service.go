package service

import (
	"github.com/dgrijalva/jwt-go"
	"net/http"
)

type JwtService interface {
	GetAuthentication(token *jwt.Token, request *http.Request) (Authentication, error)
}
