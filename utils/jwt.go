package utils

import (
	"crypto/rsa"
	"github.com/dgrijalva/jwt-go"
)

type JWTHelper struct {
	publicKey  *rsa.PublicKey
	privateKey *rsa.PrivateKey
}

func NewJWTHelper(jwtPublic string, jwtPrivate string) (*JWTHelper, error) {
	var pubKey *rsa.PublicKey
	var privKey *rsa.PrivateKey
	var err error
	if len(jwtPublic) > 0 {
		pubKey, err = jwt.ParseRSAPublicKeyFromPEM([]byte(jwtPublic))
		if err != nil {
			return nil, err
		}
	}
	if len(jwtPrivate) > 0 {
		privKey, err = jwt.ParseRSAPrivateKeyFromPEM([]byte(jwtPrivate))
		if err != nil {
			return nil, err
		}
	}
	return &JWTHelper{
		publicKey:  pubKey,
		privateKey: privKey,
	}, nil
}

func (h *JWTHelper) Generate(claims jwt.Claims) (string, error) {
	t := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"), claims)
	return t.SignedString(h.privateKey)
}

func (h *JWTHelper) Parse(tokenString string) (*jwt.Token, error) {
	jwtParse := jwt.Parser{SkipClaimsValidation: false}
	return jwtParse.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return h.publicKey, nil
	})
}

func (h *JWTHelper) ParseWithClaims(tokenString string, claims jwt.Claims) (*jwt.Token, error) {
	jwtParse := jwt.Parser{SkipClaimsValidation: false}
	return jwtParse.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return h.publicKey, nil
	})
}

func (h *JWTHelper) Sign(data []byte) (signature string, err error) {
	return jwt.GetSigningMethod("RS256").Sign(string(data), h.privateKey)
}

func (h *JWTHelper) Verify(data []byte, signature string) (err error) {
	return jwt.GetSigningMethod("RS256").Verify(string(data), signature, h.publicKey)
}
