package filter

import (
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/dgrijalva/jwt-go/request"
	"gitlab.id.vin/vincart/golib-security/web/auth/authen"
	"gitlab.id.vin/vincart/golib-security/web/config"
	"gitlab.id.vin/vincart/golib-security/web/constant"
	"gitlab.id.vin/vincart/golib-security/web/service"
	"gitlab.id.vin/vincart/golib/web/log"
	"net/http"
)

func JwtAuthSecurityFilter(properties *config.HttpSecurityProperties) (SecurityFilter, error) {
	jwtKeyFunc, err := getJwtPublicKeyFunc(&properties.Jwt)
	if err != nil {
		return nil, err
	}
	jwtService, err := getJwtService(&properties.Jwt)
	if err != nil {
		return nil, err
	}
	jwtExtractor := request.AuthorizationHeaderExtractor
	jwtParser := request.WithParser(&jwt.Parser{ValidMethods: []string{properties.Jwt.Algorithm}})
	return func(next SecurityHandler) SecurityHandler {
		return func(w http.ResponseWriter, r *http.Request) authen.Authentication {
			// Parse token from request
			token, err := request.ParseFromRequest(r, jwtExtractor, jwtKeyFunc, jwtParser)
			if err != nil {
				log.Info(r.Context(), "Invalid JWT. Error [%s]", err.Error())
				return next(w, r)
			}
			// Get authentication by token
			authentication, err := jwtService.GetAuthentication(token, r)
			if err != nil {
				log.Info(r.Context(), "Cannot get authentication. Error [%v]", err.Error())
				return next(w, r)
			}
			return authentication
		}
	}, nil
}

func getJwtService(props *config.JwtSecurityProperties) (service.JwtService, error) {
	switch props.Type {
	case constant.JwtTokenMobile:
		return service.NewJwtMobileService(), nil
	default:
		return nil, fmt.Errorf("unsupported jwt type: [%s]", props.Type)
	}
}

func getJwtPublicKeyFunc(props *config.JwtSecurityProperties) (func(token *jwt.Token) (interface{}, error), error) {
	if len(props.PublicKey) == 0 {
		return nil, errors.New("jwt public key must be defined when using jwt authentication")
	}
	var err error
	var publicKey interface{}
	if len(props.PublicKey) > 0 {
		if props.IsAlgEs() {
			publicKey, err = jwt.ParseECPublicKeyFromPEM([]byte(props.PublicKey))
		} else if props.IsAlgRs() {
			publicKey, err = jwt.ParseRSAPublicKeyFromPEM([]byte(props.PublicKey))
		} else {
			err = fmt.Errorf("unsupported jwt algorithm: [%v], required startswith RS or ES",
				props.Algorithm)
		}
		if err != nil {
			return nil, err
		}
	}
	return func(token *jwt.Token) (interface{}, error) {
		return publicKey, nil
	}, nil
}
