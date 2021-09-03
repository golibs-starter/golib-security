package golibsec

import (
	"errors"
	"fmt"
	"gitlab.id.vin/vincart/golib-security/crypto"
	"gitlab.id.vin/vincart/golib-security/utils"
	"gitlab.id.vin/vincart/golib-security/web/auth/authen"
	"gitlab.id.vin/vincart/golib-security/web/auth/user"
	"gitlab.id.vin/vincart/golib-security/web/config"
	"gitlab.id.vin/vincart/golib-security/web/filter"
	"go.uber.org/fx"
)

func BasicAuthOpt() fx.Option {
	return fx.Provide(fx.Annotated{
		Group:  "authentication_filter",
		Target: NewBasicAuthFilter,
	})
}

type BasicAuthFilterIn struct {
	fx.In
	SecurityProperties  *config.HttpSecurityProperties
	AuthProviderManager *authen.ProviderManager
}

func NewBasicAuthFilter(in BasicAuthFilterIn) (filter.AuthenticationFilter, error) {
	if in.SecurityProperties.BasicAuth == nil {
		return nil, errors.New("missing Basic Auth config")
	}
	if in.SecurityProperties.BasicAuth.Users == nil || len(in.SecurityProperties.BasicAuth.Users) == 0 {
		return nil, errors.New("missing Basic Auth Users config")
	}
	users := getSimpleUsersFromBasicAuthUsers(in.SecurityProperties.BasicAuth.Users)
	userDetailsService := user.NewInMemUserDetailsService(users)
	passwordEncoder := crypto.NewNoOpPasswordEncoder()
	in.AuthProviderManager.AddProvider(authen.NewUsernamePasswordAuthProvider(userDetailsService, passwordEncoder))
	basicAuthFilter, err := filter.BasicAuthSecurityFilter()
	if err != nil {
		return nil, fmt.Errorf("cannot init Basic Auth Security Filter: [%v]", err)
	}
	return basicAuthFilter, nil
}

func getSimpleUsersFromBasicAuthUsers(basicUsers []*config.BasicAuthProperties) []user.Details {
	users := make([]user.Details, 0)
	if basicUsers == nil {
		return users
	}
	for _, basicUser := range basicUsers {
		authorities := utils.ConvertRolesToSimpleAuthorities(basicUser.Roles)
		users = append(users, user.NewSimpleUserDetails(basicUser.Username, basicUser.Password, authorities))
	}
	return users
}
