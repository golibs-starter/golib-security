package config

type HttpSecurityProperties struct {
	PredefinedPublicUrls []string
	PublicUrls           []string
	ProtectedUrls        []UrlToRole
	BasicAuth            BasicSecurityProperties
	Jwt                  JwtSecurityProperties
}

func (h HttpSecurityProperties) Prefix() string {
	return "vinid.security.http"
}

type UrlToRole struct {
	Method                             string
	UrlPattern                         string
	Roles                              []string
	UnauthorizedWwwAuthenticateHeaders string
}
