package tokens

import (
	"fmt"
	"time"

	"StudyProject/app/entity"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

type TokensUC struct {
	secret string
}

func NewUcHandler(secret string) *TokensUC {
	return &TokensUC{secret: secret}
}

func (uc *TokensUC) GenerateTokens(params entity.TokensParams) (entity.RawTokens, error) {
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

func (uc *TokensUC) CheckTokenPair(tokens entity.RawTokens) (entity.TokensClaims, bool, error) {
	accessToken, err := jwt.ParseWithClaims(tokens.AccessToken, &entity.TokensClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(uc.secret), nil
	})
	if err != nil {
		return entity.TokensClaims{}, false, err
	}

	if accessToken == nil || !accessToken.Valid {
		return entity.TokensClaims{}, false, entity.ErrInvalidAccessToken
	}

	claims, ok := accessToken.Claims.(*entity.TokensClaims)
	if !ok {
		return entity.TokensClaims{}, false, entity.ErrRetrievingTokenClaims
	}

	data := fmt.Sprintf("%s%s%s%s%s", claims.UserGUID, claims.SessionID, claims.UserIP, uc.secret, tokens.AccessToken)
	err = bcrypt.CompareHashAndPassword(tokens.RefreshToken, []byte(data))
	if err != nil {
		return entity.TokensClaims{}, false, entity.ErrMismatchedToken
	}

	return *claims, true, nil
}

func (uc *TokensUC) generateAccessToken(params entity.TokensParams) (string, error) {
	// TODO добавить валидатор
	claims := jwt.MapClaims{
		"login":      params.UserLogin,
		"guid":       params.UserGUID,
		"session_id": params.SessionID,
		"ip":         params.UserIP,
		"exp":        time.Now().Add(entity.ATExpiredValue).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	return token.SignedString([]byte(uc.secret))
}

func (uc *TokensUC) generateRefreshToken(params entity.TokensParams, accessToken string) ([]byte, error) {
	// TODO добавить валидатор
	data := fmt.Sprintf("%s%s%s%s%s", params.UserGUID, params.SessionID, params.UserIP, uc.secret, accessToken)

	blockSize := 72
	var finalHash []byte
	for i := 0; i < len(data); i += blockSize {
		end := i + blockSize
		if end > len(data) {
			end = len(data)
		}
		blockHash, err := bcrypt.GenerateFromPassword([]byte(data[i:end]), bcrypt.DefaultCost)
		if err != nil {
			return nil, err
		}

		finalHash = append(finalHash, blockHash...)
	}

	return finalHash, nil
}

func (uc *TokensUC) GetUserParams(accessToken string) (entity.TokensClaims, error) {
	token, err := jwt.ParseWithClaims(accessToken, &entity.TokensClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(uc.secret), nil
	})
	if err != nil {
		return entity.TokensClaims{}, err
	}

	claims, ok := token.Claims.(*entity.TokensClaims)
	if !ok {
		return entity.TokensClaims{}, entity.ErrRetrievingTokenClaims
	}

	return *claims, nil
}

func (uc *TokensUC) CheckAccessToken(accessToken string) (bool, error) {
	token, err := jwt.ParseWithClaims(accessToken, &entity.TokensClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(uc.secret), nil
	})
	if err != nil {
		return false, err
	}

	if token == nil || !token.Valid {
		return false, entity.ErrInvalidAccessToken
	}
	return true, nil
}
