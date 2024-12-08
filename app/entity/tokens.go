package entity

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type TokensParams struct {
	UserLogin string
	UserGUID  string
	UserIP    string
	SessionID string
}

type RawTokens struct {
	AccessToken  string
	RefreshToken []byte
}

type TokensClaims struct {
	UserLogin string `json:"login"`
	UserGUID  string `json:"guid"`
	SessionID string `json:"session_id"`
	UserIP    string `json:"ip"`
	Exp       int64  `json:"exp"`
	jwt.RegisteredClaims
}

type UserParams struct {
	Login string
	GUID  string
}

var RTExpiredValue = time.Minute * 10
var ATExpiredValue = time.Minute * 2
