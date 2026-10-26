package repository

import (
	"context"
	"errors"

	"github.com/LeezyWannaFall/Kacpersky_2026_testovoe/internal/model"
	"github.com/LeezyWannaFall/Kacpersky_2026_testovoe/internal/service"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Postgres struct {
	pool *pgxpool.Pool
}

func NewPostgres(pool *pgxpool.Pool) *Postgres {
	return &Postgres{pool: pool}
}

func (r *Postgres) Create(ctx context.Context, threat *model.Threat) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO threats (md5, name, description, severity, type, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`, threat.MD5, threat.Name, threat.Description, threat.Severity, threat.Type, threat.CreatedAt, threat.UpdatedAt)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return service.ErrConflict
		}
		return err
	}
	return nil
}

func (r *Postgres) Get(ctx context.Context, md5 string) (*model.Threat, error) {
	threat := new(model.Threat)
	err := r.pool.QueryRow(ctx, `
		SELECT md5, name, description, severity, type, created_at, updated_at
		FROM threats WHERE md5 = $1
	`, md5).Scan(&threat.MD5, &threat.Name, &threat.Description, &threat.Severity, &threat.Type, &threat.CreatedAt, &threat.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, service.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return threat, nil
}

func (r *Postgres) Update(ctx context.Context, threat *model.Threat) error {
	tag, err := r.pool.Exec(ctx, `
		UPDATE threats
		SET name = $2, description = $3, severity = $4, type = $5, updated_at = $6
		WHERE md5 = $1
	`, threat.MD5, threat.Name, threat.Description, threat.Severity, threat.Type, threat.UpdatedAt)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return service.ErrNotFound
	}
	return nil
}
