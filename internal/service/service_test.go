package service

import (
	"context"
	"errors"
	"testing"

	"github.com/LeezyWannaFall/Kacpersky_2026_testovoe/internal/model"
)

const testMD5 = "d41d8cd98f00b204e9800998ecf8427e"

type fakeRepository struct {
	threat *model.Threat
	err    error
}

func (r *fakeRepository) Create(_ context.Context, threat *model.Threat) error {
	if r.err != nil {
		return r.err
	}
	r.threat = threat
	return nil
}

func (r *fakeRepository) Get(_ context.Context, _ string) (*model.Threat, error) {
	if r.err != nil {
		return nil, r.err
	}
	if r.threat == nil {
		return nil, ErrNotFound
	}
	copy := *r.threat
	return &copy, nil
}

func (r *fakeRepository) Update(_ context.Context, threat *model.Threat) error {
	if r.err != nil {
		return r.err
	}
	if r.threat == nil {
		return ErrNotFound
	}
	r.threat = threat
	return nil
}

func TestCreate(t *testing.T) {
	repository := &fakeRepository{}
	threat, err := New(repository).Create(context.Background(), testMD5, "Trojan", "details", model.SeverityHigh, "malware")
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if threat.MD5 != testMD5 || repository.threat != threat {
		t.Fatalf("Create() did not persist returned threat")
	}
}

func TestCreateReturnsConflict(t *testing.T) {
	repository := &fakeRepository{err: ErrConflict}
	_, err := New(repository).Create(context.Background(), testMD5, "Trojan", "", model.SeverityHigh, "")
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("Create() error = %v, want %v", err, ErrConflict)
	}
}

func TestGetReturnsNotFound(t *testing.T) {
	_, err := New(&fakeRepository{}).Get(context.Background(), testMD5)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get() error = %v, want %v", err, ErrNotFound)
	}
}

func TestGetNormalizesMD5(t *testing.T) {
	repository := &fakeRepository{}
	_, _ = New(repository).Create(context.Background(), testMD5, "Trojan", "", model.SeverityHigh, "")
	threat, err := New(repository).Get(context.Background(), "D41D8CD98F00B204E9800998ECF8427E")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if threat.MD5 != testMD5 {
		t.Fatalf("MD5 = %q, want %q", threat.MD5, testMD5)
	}
}

func TestUpdateReplacesFields(t *testing.T) {
	old, err := model.NewThreat(testMD5, "Old", "old details", model.SeverityLow, "old type")
	if err != nil {
		t.Fatal(err)
	}
	repository := &fakeRepository{threat: old}
	updated, err := New(repository).Update(context.Background(), testMD5, "New", "new details", model.SeverityCritical, "new type")
	if err != nil {
		t.Fatalf("Update() error = %v", err)
	}
	if updated.Name != "New" || updated.Description != "new details" || updated.Severity != "critical" || updated.Type != "new type" {
		t.Fatalf("Update() returned unexpected threat: %+v", updated)
	}
	if !updated.UpdatedAt.After(old.CreatedAt) && !updated.UpdatedAt.Equal(old.CreatedAt) {
		t.Fatalf("UpdatedAt = %v, want >= CreatedAt %v", updated.UpdatedAt, old.CreatedAt)
	}
}

func TestUpdateReturnsNotFound(t *testing.T) {
	_, err := New(&fakeRepository{}).Update(context.Background(), testMD5, "New", "", model.SeverityMedium, "")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Update() error = %v, want %v", err, ErrNotFound)
	}
}
