package middleware

import (
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/dgrijalva/jwt-go/request"
	"gitlab.id.vin/vincart/golib-security/web/config"
	"gitlab.id.vin/vincart/golib-security/web/constant"
	"gitlab.id.vin/vincart/golib-security/web/service"
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
				// TODO response error
				return
			}
			// Parse token from request
			token, err := request.ParseFromRequest(r, jwtExtractor, jwtKeyFunc)
			if err != nil {
				// TODO response error
				return
			}
			_, err = jwtService.GetAuthentication(token, r)
			if err != nil {
				// TODO response error
				return
			}
			//getOrCreateRequestAttributes(r).CorrelationId = getOrNewCorrelationId(r)
			next.ServeHTTP(w, r)
		})
	}, nil
}

func isRequestMatched(r *http.Request, protectedUrls []config.UrlToRole) bool {
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
	return func(token *jwt.Token) (interface{}, error) {
		// Validate the algorithm is what you expect
		if token.Method.Alg() != props.Algorithm {
			return nil, fmt.Errorf("unexpected jwt signing method: [%v], required [%s]",
				token.Method.Alg(), props.Algorithm)
		}
		return []byte(props.PublicKey), nil
	}, nil
}
