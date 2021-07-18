package config

type JwtSecurityProperties struct {
	PublicKey     string
	IgnoreFailure bool
	Algorithm     string `default:"RSA"`
	Type          string `default:"JWT_TOKEN_MOBILE"`
}
