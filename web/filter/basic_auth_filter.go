package filter

import (
	"encoding/base64"
	"github.com/pkg/errors"
	"gitlab.id.vin/vincart/golib-security/web/auth/authen"
	"gitlab.id.vin/vincart/golib-security/web/constant"
	"gitlab.id.vin/vincart/golib/web/log"
	"net/http"
	"strings"
)

const AuthorizationBasicScheme = "Basic"

func BasicAuthSecurityFilter() (AuthenticationFilter, error) {
	return func(next AuthenticationHandler) AuthenticationHandler {
		return func(w http.ResponseWriter, r *http.Request) authen.Authentication {
			header := strings.TrimSpace(r.Header.Get(constant.HeaderAuthorization))
			if header == "" || !startsWithBasicScheme(header) {
				log.Debug(r.Context(), "Skip basic auth filter due by Authorization header is not starts with [%s]",
					AuthorizationBasicScheme)
				return next(w, r)
			}
			token := extractTokenFromBasicHeader(header)
			authentication, err := extractAuthenticationFromToken(token)
			if err != nil {
				log.Info(r.Context(), "Invalid Basic Auth Token. Error [%s]", err.Error())
				return next(w, r)
			}
			return authentication
		}
	}, nil
}

func startsWithBasicScheme(header string) bool {
	return strings.HasPrefix(header, AuthorizationBasicScheme) ||
		strings.HasPrefix(header, strings.ToLower(AuthorizationBasicScheme)) ||
		strings.HasPrefix(header, strings.ToUpper(AuthorizationBasicScheme))
}

func extractTokenFromBasicHeader(header string) string {
	if len(header) < 6 {
		return ""
	}
	return strings.TrimSpace(header[6:])
}

func extractAuthenticationFromToken(token string) (*authen.UsernamePasswordAuthentication, error) {
	decodedBytes, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return nil, errors.WithMessage(err, "invalid basic auth token")
	}
	decodedString := string(decodedBytes)
	delim := strings.Index(decodedString, ":")
	if delim == -1 {
		return nil, errors.New("missing delim char in basic auth token")
	}
	username := decodedString[0:delim]
	password := decodedString[delim+1:]
	return authen.NewUsernamePasswordAuthentication(username, password, nil), nil
}
