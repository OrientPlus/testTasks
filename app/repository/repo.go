package repository

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"StudyProject/app/entity"
	_ "github.com/lib/pq"
)

type Repo struct {
	db *sql.DB
}

type TokenDTO struct {
	Token     []byte
	SessionID string
	IpAddress string
	ExpTime   time.Time
}

func NewRepo(creds string) (*Repo, error) {
	repo := &Repo{}

	var err error
	repo.db, err = sql.Open("postgres", creds)
	err = repo.db.Ping()
	return repo, err
}

func (r *Repo) Close() error {
	return r.db.Close()
}

func (r *Repo) AddToken(ctx context.Context, params TokenDTO) error {
	if ctx == nil || len(params.Token) == 0 || params.SessionID == "" || params.IpAddress == "" || params.ExpTime.IsZero() {
		return entity.ErrEmptyInputArgument
	}

	query := `INSERT INTO tokens (refresh_token, session_id, ip, exp_time) VALUES ($1, $2, $3, $4);`
	_, err := r.db.ExecContext(ctx, query, params.Token, params.SessionID, params.IpAddress, params.ExpTime)

	return err
}

func (r *Repo) RemoveToken(ctx context.Context, sessionID string) error {
	if ctx == nil || sessionID == "" {
		return entity.ErrEmptyInputArgument
	}

	query := `DELETE FROM tokens WHERE session_id = $1;`
	_, err := r.db.ExecContext(ctx, query, sessionID)

	return err
}

func (r *Repo) GetRefreshToken(ctx context.Context, sessionID string) (TokenDTO, error) {
	if ctx == nil || sessionID == "" {
		return TokenDTO{}, entity.ErrEmptyInputArgument
	}

	query := `SELECT refresh_token, exp_time, ip FROM tokens WHERE session_id = $1;`
	var response TokenDTO
	err := r.db.QueryRowContext(ctx, query, sessionID).Scan(&response.Token, &response.ExpTime, &response.IpAddress)
	if err != nil && errors.Is(err, sql.ErrNoRows) {
		return TokenDTO{}, entity.ErrTokenNotFound
	}

	response.SessionID = sessionID
	return response, err
}
