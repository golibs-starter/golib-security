package config

type BasicSecurityProperties struct {
	Users []BasicAuthProperties
}

type BasicAuthProperties struct {
	Username string
	Password string
	Roles    []string
}
