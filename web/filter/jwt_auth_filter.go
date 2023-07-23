package filter

import (
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v4"
	"github.com/golang-jwt/jwt/v4/request"
	"gitlab.com/golibs-starter/golib-security/web/auth/authen"
	"gitlab.com/golibs-starter/golib-security/web/config"
	"gitlab.com/golibs-starter/golib-security/web/constant"
	"gitlab.com/golibs-starter/golib-security/web/service"
	"gitlab.com/golibs-starter/golib/log"
	"net/http"
)

func JwtAuthSecurityFilter(props *config.JwtSecurityProperties) (AuthenticationFilter, error) {
	jwtKeyFunc, err := getJwtPublicKeyFunc(props)
	if err != nil {
		return nil, err
	}
	jwtService, err := getJwtService(props)
	if err != nil {
		return nil, err
	}
	jwtExtractor := request.AuthorizationHeaderExtractor
	jwtParser := request.WithParser(&jwt.Parser{ValidMethods: []string{props.Algorithm}})
	return func(next AuthenticationHandler) AuthenticationHandler {
		return func(w http.ResponseWriter, r *http.Request) authen.Authentication {
			logger := log.WithCtx(r.Context())
			// Parse token from request
			token, err := request.ParseFromRequest(r, jwtExtractor, jwtKeyFunc, jwtParser)
			if err != nil {
				logger.WithErrors(err).Info("Invalid JWT")
				return next(w, r)
			}
			// Get authentication by token
			authentication, err := jwtService.GetAuthentication(token, r)
			if err != nil {
				logger.WithErrors(err).Info("Cannot get authentication")
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
