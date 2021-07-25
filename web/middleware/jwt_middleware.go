package middleware

import (
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/dgrijalva/jwt-go/request"
	"gitlab.id.vin/vincart/golib-security/web/config"
	"gitlab.id.vin/vincart/golib-security/web/constant"
	"gitlab.id.vin/vincart/golib-security/web/service"
	"gitlab.id.vin/vincart/golib/exception"
	"gitlab.id.vin/vincart/golib/web/context"
	"gitlab.id.vin/vincart/golib/web/log"
	"gitlab.id.vin/vincart/golib/web/resource"
	"net/http"
)

func JwtAuth(properties *config.HttpSecurityProperties) (func(next http.Handler) http.Handler, error) {
	jwtKeyFunc, err := getJwtPublicKeyFunc(&properties.Jwt)
	if err != nil {
		return nil, err
	}
	jwtService, err := getJwtService(&properties.Jwt)
	if err != nil {
		return nil, err
	}
	jwtExtractor := request.AuthorizationHeaderExtractor
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !isRequestMatched(r, properties.ProtectedUrls) {
				resource.WriteError(w, exception.Forbidden)
				return
			}
			// Parse token from request
			parser := request.WithParser(&jwt.Parser{ValidMethods: []string{properties.Jwt.Algorithm}})
			token, err := request.ParseFromRequest(r, jwtExtractor, jwtKeyFunc, parser)
			if err != nil {
				log.Info(r.Context(), "Invalid JWT. Error [%s]", err.Error())
				resource.WriteError(w, exception.Unauthorized)
				return
			}
			// Get authentication by token
			authentication, err := jwtService.GetAuthentication(token, r)
			if err != nil {
				log.Info(r.Context(), "Cannot get authentication. Error [%v]", err.Error())
				resource.WriteError(w, exception.Unauthorized)
				return
			}
			if !authentication.IsAuthenticated() {
				resource.WriteError(w, exception.Unauthorized)
				return
			}
			requestAttributes := context.GetRequestAttributes(r.Context())
			if requestAttributes != nil {
				requestAttributes.SecurityAttributes.UserId = authentication.GetPrincipal()
			}
			next.ServeHTTP(w, r)
		})
	}, nil
}

func isRequestMatched(r *http.Request, protectedUrls []*config.UrlToRole) bool {
	if len(protectedUrls) > 0 {
		uri := r.URL.RequestURI()
		for _, protectedUrl := range protectedUrls {
			if protectedUrl.Method != "" && protectedUrl.Method != r.Method {
				continue
			}
			if protectedUrl.UrlRegexp() != nil && protectedUrl.UrlRegexp().MatchString(uri) {
				return true
			}
		}
	}
	return false
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
