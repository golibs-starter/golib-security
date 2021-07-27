package config

import "strings"

type JwtSecurityProperties struct {
	PublicKey string
	Algorithm string `default:"RS256"`
	Type      string `default:"JWT_TOKEN_MOBILE"`
}

func (j JwtSecurityProperties) IsAlgRs() bool {
	return strings.HasPrefix(j.Algorithm, "RS")
}

func (j JwtSecurityProperties) IsAlgEs() bool {
	return strings.HasPrefix(j.Algorithm, "ES")
}
