package service

import (
	"errors"
	"github.com/dgrijalva/jwt-go"
	"gitlab.id.vin/vincart/golib-security/web/auth"
	"gitlab.id.vin/vincart/golib-security/web/entity"
	"gitlab.id.vin/vincart/golib/web/constant"
	"net/http"
)

type JwtMobileService struct {
}

func NewJwtMobileService() *JwtMobileService {
	return &JwtMobileService{}
}

func (j JwtMobileService) GetAuthentication(token *jwt.Token, request *http.Request) (auth.Authentication, error) {
	mapClaims := token.Claims.(jwt.MapClaims)
	userId := mapClaims["sub"].(string)
	if len(userId) == 0 {
		return nil, errors.New("missing jwt subject in the token")
	}
	return auth.NewJwtAuthentication(&entity.VinIdUserDetails{
		UserId:          userId,
		DeviceId:        request.Header.Get(constant.HeaderDeviceId),
		DeviceSessionId: request.Header.Get(constant.HeaderDeviceSessionId),
		Roles:           j.roles(),
	}, true), nil
}

func (j JwtMobileService) roles() []string {
	return []string{"ROLE_MOBILE_APP"}
}
