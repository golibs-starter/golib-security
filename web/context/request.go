package context

import (
	"context"
	"github.com/golibs-starter/golib-security/web/auth/authen"
	"github.com/golibs-starter/golib-security/web/auth/user"
	"github.com/golibs-starter/golib-security/web/config"
	"net/http"
)

const (
	MatchedUrlProtection = "MATCHED_URL_PROTECTION"
	Authentication       = "AUTHENTICATION"
)

func AttachAuthentication(r *http.Request, authentication authen.Authentication) *http.Request {
	return r.WithContext(
		context.WithValue(r.Context(), Authentication, authentication),
	)
}

func GetAuthentication(r *http.Request) authen.Authentication {
	value := r.Context().Value(Authentication)
	if value == nil {
		return nil
	}
	authentication, ok := value.(authen.Authentication)
	if !ok {
		return nil
	}
	return authentication
}

func GetUserDetails(r *http.Request) user.Details {
	authentication := GetAuthentication(r)
	if authentication == nil {
		return nil
	}
	return authentication.Details()
}

func AttachMatchedUrlProtection(r *http.Request, url *config.UrlToRole) *http.Request {
	return r.WithContext(
		context.WithValue(r.Context(), MatchedUrlProtection, url),
	)
}

func GetMatchedUrlProtection(r *http.Request) *config.UrlToRole {
	value := r.Context().Value(MatchedUrlProtection)
	if value == nil {
		return nil
	}
	matchedUrl, ok := value.(*config.UrlToRole)
	if !ok {
		return nil
	}
	return matchedUrl
}
