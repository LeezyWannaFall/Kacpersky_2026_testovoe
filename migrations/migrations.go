package migrations

import (
	"context"
	"database/sql"
	"embed"
	"fmt"

	"github.com/pressly/goose/v3"
)

//go:embed *.sql
var files embed.FS

func Apply(ctx context.Context, db *sql.DB) error {
	provider, err := goose.NewProvider(goose.DialectPostgres, db, files, goose.WithLogger(goose.NopLogger()))
	if err != nil {
		return fmt.Errorf("create goose provider: %w", err)
	}
	defer provider.Close()

	if _, err := provider.Up(ctx); err != nil {
		return fmt.Errorf("apply goose migrations: %w", err)
	}
	return nil
}
