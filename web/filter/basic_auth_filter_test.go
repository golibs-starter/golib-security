package filter

import (
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_extractTokenFromBasicHeader(t *testing.T) {
	type args struct {
		header string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "When header has len < 6 then return empty",
			args: args{header: "Basic"},
			want: "",
		},
		{
			name: "When header has len = 6 then return empty",
			args: args{header: "Basic "},
			want: "",
		},
		{
			name: "When header has len > 6 then return correct header",
			args: args{header: "Basic test"},
			want: "test",
		},
		{
			name: "When header has len > 6 and contains multiple space then return correct header",
			args: args{header: "Basic   test  "},
			want: "test",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractTokenFromBasicHeader(tt.args.header); got != tt.want {
				t.Errorf("extractTokenFromBasicHeader() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_startsWithBasicScheme(t *testing.T) {
	type args struct {
		header string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "When header starts with Basic should return true",
			args: args{header: "Basic test"},
			want: true,
		},
		{
			name: "When header starts with BASIC should return true",
			args: args{header: "BASIC test"},
			want: true,
		},
		{
			name: "When header starts with basic should return true",
			args: args{header: "basic test"},
			want: true,
		},
		{
			name: "When header not starts with Basic|BASIC|basic should return false",
			args: args{header: "bs test"},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := startsWithBasicScheme(tt.args.header); got != tt.want {
				t.Errorf("startsWithBasicScheme() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_extractAuthenticationFromToken_ShouldReturnCorrect(t *testing.T) {
	token := "ZGVtbzpzZWNyZXQ=" //demo:secret
	auth, err := extractAuthenticationFromToken(token)
	assert.Nil(t, err)
	assert.NotNil(t, auth)
	assert.NotNil(t, auth.Principal())
	assert.Equal(t, "demo", auth.Principal().(string))
	assert.NotNil(t, auth.Credentials())
	assert.Equal(t, "secret", auth.Credentials().(string))
	assert.NotNil(t, auth.Authorities())
	assert.Len(t, auth.Authorities(), 0)
}

func Test_extractAuthenticationFromToken_WhenEmptyUsername_ShouldReturnCorrect(t *testing.T) {
	token := "OnNlY3JldA==" //:secret
	auth, err := extractAuthenticationFromToken(token)
	assert.Nil(t, err)
	assert.NotNil(t, auth)
	assert.NotNil(t, auth.Principal())
	assert.Equal(t, "", auth.Principal().(string))
	assert.NotNil(t, auth.Credentials())
	assert.Equal(t, "secret", auth.Credentials().(string))
	assert.NotNil(t, auth.Authorities())
	assert.Len(t, auth.Authorities(), 0)
}

func Test_extractAuthenticationFromToken_WhenEmptyPassword_ShouldReturnCorrect(t *testing.T) {
	token := "ZGVtbzo=" //demo:
	auth, err := extractAuthenticationFromToken(token)
	assert.Nil(t, err)
	assert.NotNil(t, auth)
	assert.NotNil(t, auth.Principal())
	assert.Equal(t, "demo", auth.Principal().(string))
	assert.NotNil(t, auth.Credentials())
	assert.Equal(t, "", auth.Credentials().(string))
	assert.NotNil(t, auth.Authorities())
	assert.Len(t, auth.Authorities(), 0)
}

func Test_extractAuthenticationFromToken_WhenNotValidBase64_ShouldReturnNil(t *testing.T) {
	token := "demo:secret"
	auth, err := extractAuthenticationFromToken(token)
	assert.Nil(t, auth)
	assert.NotNil(t, err)
	assert.NotNil(t, errors.Cause(err))
}

func Test_extractAuthenticationFromToken_WhenNotContainsDelimChar_ShouldReturnNil(t *testing.T) {
	token := "ZGVtbw==" //demo
	auth, err := extractAuthenticationFromToken(token)
	assert.Nil(t, auth)
	assert.NotNil(t, err)
}
