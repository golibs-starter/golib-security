package golibsecTestUtil

import (
	"crypto/rsa"
	"github.com/golang-jwt/jwt/v4"
	"github.com/pkg/errors"
	"log"
	"time"
)

type JwtTestUtil struct {
	jwtSignKey    *rsa.PrivateKey
	jwtProperties *JwtTestProperties
}

func NewJwtTestUtil(jwtProperties *JwtTestProperties) (*JwtTestUtil, error) {
	ts := &JwtTestUtil{jwtProperties: jwtProperties}
	if err := ts.LoadJwtPrivateKey(); err != nil {
		return nil, err
	}
	return ts, nil
}

// LoadJwtPrivateKey load jwt config from properties
func (s *JwtTestUtil) LoadJwtPrivateKey() error {
	signKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(s.jwtProperties.PrivateKey))
	if err != nil {
		return errors.WithMessage(err, "Could not load jwt private key")
	}
	s.jwtSignKey = signKey
	return nil
}

// CreateJwtToken return a new jwt token
func (s *JwtTestUtil) CreateJwtToken(userId string) string {
	token := jwt.New(jwt.GetSigningMethod("RS256"))
	now := time.Now()
	token.Claims = &jwt.RegisteredClaims{
		Issuer:    "TESTER",
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(time.Minute * 1)),
		Subject:   userId,
	}
	jwtToken, err := token.SignedString(s.jwtSignKey)
	if err != nil {
		log.Fatalf("Could not create jwt token: %v", err)
	}
	return jwtToken
}
