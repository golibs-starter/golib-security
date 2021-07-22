package service

import (
	"github.com/dgrijalva/jwt-go"
	"net/http"
)

type JwtMobileService struct {
}

func NewJwtMobileService() *JwtMobileService {
	return &JwtMobileService{}
}

func (j JwtMobileService) GetAuthentication(token *jwt.Token, request *http.Request) (Authentication, error) {
	panic("implement me")
}
