-- +goose Up
CREATE TABLE threats (
    md5         VARCHAR(32) PRIMARY KEY CHECK (md5 ~ '^[a-fA-F0-9]{32}$'),
    name        TEXT NOT NULL CHECK (length(btrim(name)) > 0),
    description TEXT NOT NULL DEFAULT '',
    severity    TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    type        TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- +goose Down
DROP TABLE IF EXISTS threats;
