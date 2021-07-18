package config

type BasicSecurityProperties struct {
	Users []BasicAuthProperties `mapstructure:"users"`
}

type BasicAuthProperties struct {
	Username string   `mapstructure:"username"`
	Password string   `mapstructure:"password"`
	Roles    []string `mapstructure:"roles"`
}
