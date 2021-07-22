package entity

import "github.com/dgrijalva/jwt-go"

type VinIdUserDetails struct {
	jwt.StandardClaims
	UserId          string `json:"user_id"`
	UserName        string `json:"user_name"`
	DeviceId        string `json:"device_id"`
	DeviceSessionId string `json:"device_session_id"`
}
