package config

import (
	"net"
	"net/url"
	"os"
	"time"
)

type Config struct {
	HTTPAddr        string
	DBHost          string
	DBPort          string
	DBName          string
	DBUser          string
	DBPassword      string
	DBSSLMode       string
	ShutdownTimeout time.Duration
}

func Load() Config {
	return Config{
		HTTPAddr:        env("HTTP_ADDR", ":8080"),
		DBHost:          env("DB_HOST", "localhost"),
		DBPort:          env("DB_PORT", "5432"),
		DBName:          env("DB_NAME", "threats"),
		DBUser:          env("DB_USER", "threats"),
		DBPassword:      env("DB_PASSWORD", "threats"),
		DBSSLMode:       env("DB_SSLMODE", "disable"),
		ShutdownTimeout: 10 * time.Second,
	}
}

func (c Config) DatabaseURL() string {
	return (&url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(c.DBUser, c.DBPassword),
		Host:   net.JoinHostPort(c.DBHost, c.DBPort),
		Path:   "/" + c.DBName,
		RawQuery: url.Values{
			"sslmode": []string{c.DBSSLMode},
		}.Encode(),
	}).String()
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
