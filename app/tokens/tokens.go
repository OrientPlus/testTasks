package tokens

import (
	"fmt"
	"time"

	"StudyProject/app/entity"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

type UcHandler struct {
	secret string
}

func NewUcHandler(secret string) *UcHandler {
	return &UcHandler{secret: secret}
}

func (uc *UcHandler) GenerateTokens(params entity.TokensParams) (entity.RawTokens, error) {
	accessToken, err := uc.generateAccessToken(params)
	if err != nil {
		return entity.RawTokens{}, entity.ErrGenAccessToken
	}
	refreshToken, err := uc.generateRefreshToken(params, accessToken)
	if err != nil {
		return entity.RawTokens{}, entity.ErrGenRefreshToken
	}

	return entity.RawTokens{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func (uc *UcHandler) CheckRefreshToken(tokens entity.RawTokens) (bool, error) {
	accessToken, err := jwt.ParseWithClaims(tokens.AccessToken, &entity.TokensClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(uc.secret), nil
	})
	if err != nil {
		return false, err
	}

	if accessToken == nil || !accessToken.Valid {
		return false, entity.ErrInvalidAccessToken
	}

	claims, ok := accessToken.Claims.(*entity.TokensClaims)
	if !ok {
		return false, entity.ErrRetrievingTokenClaims
	}

	data := fmt.Sprintf("%s%s%s%s%s", claims.UserGUID, claims.SessionID, claims.UserIP, uc.secret, tokens.AccessToken)
	err = bcrypt.CompareHashAndPassword(tokens.RefreshToken, []byte(data))
	if err != nil {
		return false, entity.ErrMismatchedToken
	}

	return true, nil
}

func (uc *UcHandler) generateAccessToken(params entity.TokensParams) (string, error) {
	// TODO добавить валидатор
	claims := jwt.MapClaims{
		"user_login": params.UserLogin,
		"user_guid":  params.UserGUID,
		"session_id": params.SessionID,
		"ip":         params.UserIP,
		"exp":        time.Now().Add(15 * time.Minute).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	return token.SignedString([]byte(uc.secret))
}

func (uc *UcHandler) generateRefreshToken(params entity.TokensParams, accessToken string) ([]byte, error) {
	// TODO добавить валидатор
	data := fmt.Sprintf("%s%s%s%s%s", params.UserGUID, params.SessionID, params.UserIP, uc.secret, accessToken)
	hash, err := bcrypt.GenerateFromPassword([]byte(data), bcrypt.DefaultCost)

	return hash, err
}
