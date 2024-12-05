package repository

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"StudyProject/app/entity"
)

type Repo struct {
	db *sql.DB
}

type TokenDTO struct {
	Token     []byte
	SessionID string
	IpAddress string
	CreatedAt time.Time
}

func NewRepo(creds string) (*Repo, error) {
	repo := &Repo{}

	var err error
	repo.db, err = sql.Open("postgres", creds)
	return repo, err
}

func (r *Repo) Close() error {
	return r.db.Close()
}

func (r *Repo) AddToken(ctx context.Context, params TokenDTO) error {
	if len(params.Token) == 0 || params.SessionID == "" || params.IpAddress == "" || params.CreatedAt.IsZero() {
		return entity.ErrEmptyInputArgument
	}

	query := `INSERT INTO tokens (refresh_token, session_id, ip, created_at) VALUES ($1, $2, $3, $4)`
	_, err := r.db.ExecContext(ctx, query, params.Token, params.SessionID, params.IpAddress, time.Now())

	return err
}

func (r *Repo) RemoveToken(ctx context.Context, params TokenDTO) error {
	if len(params.Token) == 0 {
		return entity.ErrEmptyInputArgument
	}

	query := `DELETE FROM tokens WHERE refresh_token = $1`
	_, err := r.db.ExecContext(ctx, query, params.Token)

	return err
}

func (r *Repo) UpdateToken(ctx context.Context, params TokenDTO) error {
	if len(params.Token) == 0 || params.SessionID == "" || params.IpAddress == "" || params.CreatedAt.IsZero() {
		return entity.ErrEmptyInputArgument
	}

	query := `UPDATE tokens SET refresh_token = $1, created_at = $2, ip = $3 WHERE session_id = $4`
	_, err := r.db.ExecContext(ctx, query, params.Token, time.Now(), params.IpAddress, params.SessionID)

	return err
}

func (r *Repo) GetRefreshToken(ctx context.Context, sessionID string) (TokenDTO, error) {
	if sessionID == "" {
		return TokenDTO{}, entity.ErrEmptyInputArgument
	}

	query := `SELECT refresh_token, created_at, ip FROM tokens WHERE session_id = $1`
	var response TokenDTO
	err := r.db.QueryRowContext(ctx, query, sessionID).Scan(&response.Token, &response.CreatedAt, &response.IpAddress)
	if err != nil && errors.Is(err, sql.ErrNoRows) {
		return TokenDTO{}, entity.ErrTokenNotFound
	}

	return response, err
}
