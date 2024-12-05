-- +goose up

CREATE TABLE tokens (
    id int NOT NULL PRIMARY KEY,
    refresh_token BYTEA NOT NULL UNIQUE,
    session_id text NOT NULL UNIQUE,
    ip text NOT NULL,
    created_at TIMESTAMP NOT NULL
);

-- +goose Down
DROP TABLE tokens;
