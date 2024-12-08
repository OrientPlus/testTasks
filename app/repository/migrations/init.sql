CREATE TABLE tokens (
    id SERIAL PRIMARY KEY,
    refresh_token BYTEA NOT NULL UNIQUE,
    session_id text NOT NULL UNIQUE,
    ip text NOT NULL,
    exp_time TIMESTAMP WITH TIME ZONE NOT NULL
);