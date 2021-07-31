package golibsec

import (
	"github.com/stretchr/testify/assert"
	"gitlab.id.vin/vincart/golib-security/web/config"
	"testing"
)

func Test_getSimpleUsersFromBasicAuthUsers_ShouldReturnCorrect(t *testing.T) {
	basicUsers := []config.BasicAuthProperties{
		{
			Username: "user1",
			Password: "pass1",
			Roles:    nil,
		},
		{
			Username: "user2",
			Password: "pass2",
			Roles:    []string{"ADMIN", "MANAGER"},
		},
	}
	users := getSimpleUsersFromBasicAuthUsers(basicUsers)

	assert.NotNil(t, users)
	assert.Len(t, users, 2)
	assert.Equal(t, "user1", users[0].Username())
	assert.Equal(t, "pass1", users[0].Password())
	assert.NotNil(t, users[0].Authorities())
	assert.Len(t, users[0].Authorities(), 0)

	assert.Equal(t, "user2", users[1].Username())
	assert.Equal(t, "pass2", users[1].Password())
	assert.NotNil(t, users[1].Authorities())
	assert.Len(t, users[1].Authorities(), 2)
	assert.Equal(t, "ROLE_ADMIN", users[1].Authorities()[0].Authority())
	assert.Equal(t, "ROLE_MANAGER", users[1].Authorities()[1].Authority())
}

func Test_getSimpleUsersFromBasicAuthUsers_WhenBasicAuthNil_ShouldReturnEmpty(t *testing.T) {
	users := getSimpleUsersFromBasicAuthUsers(nil)
	assert.NotNil(t, users)
	assert.Len(t, users, 0)
}
