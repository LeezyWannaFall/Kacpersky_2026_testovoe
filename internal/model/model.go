package model

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

var (
	ErrInvalidMD5      = errors.New("invalid MD5")
	ErrInvalidName     = errors.New("name must not be empty")
	ErrInvalidSeverity = errors.New("invalid severity")
	md5Pattern         = regexp.MustCompile(`^[a-fA-F0-9]{32}$`)
)

type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

type Threat struct {
	MD5         string
	Name        string
	Description string
	Severity    Severity
	Type        string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

func NewThreat(md5, name, description string, severity Severity, threatType string) (*Threat, error) {
	md5 = strings.ToLower(md5)
	if !md5Pattern.MatchString(md5) {
		return nil, ErrInvalidMD5
	}
	if strings.TrimSpace(name) == "" {
		return nil, ErrInvalidName
	}
	if !severity.Valid() {
		return nil, fmt.Errorf("%w: %q", ErrInvalidSeverity, severity)
	}

	now := time.Now().UTC()
	return &Threat{
		MD5:         md5,
		Name:        name,
		Description: description,
		Severity:    severity,
		Type:        threatType,
		CreatedAt:   now,
		UpdatedAt:   now,
	}, nil
}

func (s Severity) Valid() bool {
	switch s {
	case SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
		return true
	default:
		return false
	}
}

func ValidateMD5(value string) error {
	if !md5Pattern.MatchString(value) {
		return ErrInvalidMD5
	}
	return nil
}
