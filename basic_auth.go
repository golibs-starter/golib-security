package golibsec

import (
	"fmt"
	"gitlab.id.vin/vincart/golib-security/crypto"
	"gitlab.id.vin/vincart/golib-security/utils"
	"gitlab.id.vin/vincart/golib-security/web/auth/authen"
	"gitlab.id.vin/vincart/golib-security/web/auth/user"
	"gitlab.id.vin/vincart/golib-security/web/config"
	"gitlab.id.vin/vincart/golib-security/web/filter"
)

func UsingBasicAuth() AuthFilter {
	return func(props *config.HttpSecurityProperties, authPrm *authen.ProviderManager) filter.AuthenticationFilter {
		users := getSimpleUsersFromBasicAuthUsers(props.BasicAuth.Users)
		userDetailsService := user.NewInMemUserDetailsService(users)
		passwordEncoder := crypto.NewNoOpPasswordEncoder()
		authPrm.AddProvider(authen.NewUsernamePasswordAuthProvider(userDetailsService, passwordEncoder))
		basicAuthFilter, err := filter.BasicAuthSecurityFilter()
		if err != nil {
			panic(fmt.Sprintf("Cannot init Basic Auth Security Filter: [%v]", err))
		}
		return basicAuthFilter
	}
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
