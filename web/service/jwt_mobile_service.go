package service

import (
	"errors"
	"github.com/golang-jwt/jwt/v4"
	"github.com/golibs-starter/golib-security/web/auth/authen"
	"github.com/golibs-starter/golib-security/web/auth/authorization/authority"
	"github.com/golibs-starter/golib-security/web/auth/user"
	"net/http"
)

type JwtMobileService struct {
}

func NewJwtMobileService() *JwtMobileService {
	return &JwtMobileService{}
}

func (j JwtMobileService) GetAuthentication(token *jwt.Token, request *http.Request) (authen.Authentication, error) {
	mapClaims := token.Claims.(jwt.MapClaims)
	userId := mapClaims["sub"].(string)
	if len(userId) == 0 {
		return nil, errors.New("missing jwt subject in the token")
	}
	authorities := []authority.GrantedAuthority{authority.NewSimpleGrantedAuthority(j.role())}
	userDetails := user.NewSimpleUserDetails(userId, authorities)
	return authen.NewJwtTokenAuthentication(userDetails, authorities, mapClaims), nil
}

func (j JwtMobileService) role() string {
	return "ROLE_MOBILE_APP"
}
