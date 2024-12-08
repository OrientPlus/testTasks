package entity

import (
	"errors"
)

var (
	ErrTokenNotFound         = errors.New("repo: token not foud")
	ErrEmptyInputArgument    = errors.New("repo: empty input argument")
	ErrCannotInitDatabase    = errors.New("server: cannot init database")
	ErrCannotListenAndServe  = errors.New("server: cannot listen/serve")
	ErrGenAccessToken        = errors.New("server: cannot generate access token")
	ErrGenRefreshToken       = errors.New("server: cannot generate refresh token")
	ErrInvalidAccessToken    = errors.New("server: invalid access token")
	ErrRetrievingTokenClaims = errors.New("server: cannot retrieve token claims")
	ErrMismatchedToken       = errors.New("server: mismatched token")
	ErrEnvArgumentEmpty      = errors.New("env: argument is empty")
)
