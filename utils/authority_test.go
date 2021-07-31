package utils

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestConvertRolesToSimpleAuthorities_ShouldReturnCorrect(t *testing.T) {
	roles := []string{"ADMIN", "MANAGER"}
	authorities := ConvertRolesToSimpleAuthorities(roles)

	assert.NotNil(t, authorities)
	assert.Len(t, authorities, 2)
	assert.Equal(t, "ROLE_ADMIN", authorities[0].Authority())
	assert.Equal(t, "ROLE_MANAGER", authorities[1].Authority())
}

func TestConvertRolesToSimpleAuthorities_WhenRolesNil_ShouldReturnEmpty(t *testing.T) {
	authorities := ConvertRolesToSimpleAuthorities(nil)
	assert.NotNil(t, authorities)
	assert.Len(t, authorities, 0)
}
