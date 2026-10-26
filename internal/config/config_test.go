package config

import (
	"net/url"
	"testing"
)

func TestDatabaseURLEscapesCredentials(t *testing.T) {
	cfg := Config{
		DBHost: "db", DBPort: "5432", DBName: "threats", DBUser: "api user",
		DBPassword: "p@ss:/word", DBSSLMode: "disable",
	}

	parsed, err := url.Parse(cfg.DatabaseURL())
	if err != nil {
		t.Fatalf("DatabaseURL() produced invalid URL: %v", err)
	}
	if parsed.User.Username() != cfg.DBUser {
		t.Errorf("username = %q, want %q", parsed.User.Username(), cfg.DBUser)
	}
	password, _ := parsed.User.Password()
	if password != cfg.DBPassword {
		t.Errorf("password = %q, want %q", password, cfg.DBPassword)
	}
}
