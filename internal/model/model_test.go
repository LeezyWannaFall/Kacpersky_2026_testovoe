package model

import (
	"errors"
	"testing"
)

func TestValidateMD5(t *testing.T) {
	tests := []struct {
		name  string
		value string
		valid bool
	}{
		{name: "lowercase", value: "d41d8cd98f00b204e9800998ecf8427e", valid: true},
		{name: "uppercase", value: "D41D8CD98F00B204E9800998ECF8427E", valid: true},
		{name: "too short", value: "d41d8cd98f00b204e9800998ecf8427", valid: false},
		{name: "non hexadecimal", value: "d41d8cd98f00b204e9800998ecf8427g", valid: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateMD5(tt.value)
			if tt.valid && err != nil {
				t.Fatalf("ValidateMD5() error = %v", err)
			}
			if !tt.valid && !errors.Is(err, ErrInvalidMD5) {
				t.Fatalf("ValidateMD5() error = %v, want %v", err, ErrInvalidMD5)
			}
		})
	}
}

func TestSeverityValid(t *testing.T) {
	for _, severity := range []Severity{SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical} {
		if !severity.Valid() {
			t.Errorf("%q should be valid", severity)
		}
	}
	if Severity("urgent").Valid() {
		t.Error("urgent should be invalid")
	}
}

func TestNewThreatValidatesAndNormalizes(t *testing.T) {
	threat, err := NewThreat("D41D8CD98F00B204E9800998ECF8427E", "Trojan", "", SeverityHigh, "")
	if err != nil {
		t.Fatalf("NewThreat() error = %v", err)
	}
	if threat.MD5 != "d41d8cd98f00b204e9800998ecf8427e" {
		t.Errorf("MD5 = %q, want lowercase", threat.MD5)
	}
	if threat.CreatedAt.IsZero() || threat.UpdatedAt.IsZero() {
		t.Error("timestamps should be set")
	}
}

func TestNewThreatRejectsInvalidFields(t *testing.T) {
	tests := []struct {
		name       string
		md5        string
		threatName string
		severity   Severity
		wantErr    error
	}{
		{name: "invalid md5", md5: "bad", threatName: "Trojan", severity: SeverityHigh, wantErr: ErrInvalidMD5},
		{name: "blank name", md5: "d41d8cd98f00b204e9800998ecf8427e", threatName: "  ", severity: SeverityHigh, wantErr: ErrInvalidName},
		{name: "invalid severity", md5: "d41d8cd98f00b204e9800998ecf8427e", threatName: "Trojan", severity: "urgent", wantErr: ErrInvalidSeverity},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewThreat(tt.md5, tt.threatName, "", tt.severity, "")
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("NewThreat() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}
