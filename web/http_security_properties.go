package web

type HttpSecurityProperties struct {
	PredefinedPublicUrls []string                `mapstructure:"predefined_public_urls"`
	PublicUrls           []string                `mapstructure:"public_urls"`
	ProtectedUrls        []UrlToRole             `mapstructure:"protected_urls"`
	BasicAuth            BasicSecurityProperties `mapstructure:"basic_auth"`
}

func (h HttpSecurityProperties) Prefix() string {
	return "vinid.security.http"
}

type BasicSecurityProperties struct {
	Users []BasicAuthProperties `mapstructure:"users"`
}

type BasicAuthProperties struct {
	Username string   `mapstructure:"username"`
	Password string   `mapstructure:"password"`
	Roles    []string `mapstructure:"roles"`
}

type UrlToRole struct {
	Method                             string   `mapstructure:"method"`
	UrlPattern                         string   `mapstructure:"url_pattern"`
	Roles                              []string `mapstructure:"roles"`
	UnauthorizedWwwAuthenticateHeaders string   `mapstructure:"unauthorized_www_authenticate_headers"`
}
