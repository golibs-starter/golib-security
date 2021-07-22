package config

type JwtSecurityProperties struct {
	PublicKey string
	Algorithm string `default:"RSA"`
	Type      string `default:"JWT_TOKEN_MOBILE"`
}
