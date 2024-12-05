package entity

import "github.com/golang-jwt/jwt/v5"

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
	UserLogin string `json:"user_login"`
	UserGUID  string `json:"user_guid"`
	SessionID string `json:"session_id"`
	UserIP    string `json:"ip"`
	Exp       string `json:"exp"`
	jwt.RegisteredClaims
}
