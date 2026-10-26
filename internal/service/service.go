package service

import (
	"context"
	"errors"
	"time"

	"github.com/LeezyWannaFall/Kacpersky_2026_testovoe/internal/model"
)

var (
	ErrNotFound = errors.New("threat not found")
	ErrConflict = errors.New("threat already exists")
)

type Repository interface {
	Create(ctx context.Context, threat *model.Threat) error
	Get(ctx context.Context, md5 string) (*model.Threat, error)
	Update(ctx context.Context, threat *model.Threat) error
}

type Service struct {
	repository Repository
}

func New(repository Repository) *Service {
	return &Service{repository: repository}
}

func (s *Service) Create(ctx context.Context, md5, name, description string, severity model.Severity, threatType string) (*model.Threat, error) {
	threat, err := model.NewThreat(md5, name, description, severity, threatType)
	if err != nil {
		return nil, err
	}

	if err := s.repository.Create(ctx, threat); err != nil {
		return nil, err
	}
	return threat, nil
}

func (s *Service) Get(ctx context.Context, md5 string) (*model.Threat, error) {
	if err := model.ValidateMD5(md5); err != nil {
		return nil, err
	}
	return s.repository.Get(ctx, md5)
}

func (s *Service) Update(ctx context.Context, md5, name, description string, severity model.Severity, threatType string) (*model.Threat, error) {
	if err := model.ValidateMD5(md5); err != nil {
		return nil, err
	}
	if _, err := model.NewThreat(md5, name, description, severity, threatType); err != nil {
		return nil, err
	}

	threat, err := s.repository.Get(ctx, md5)
	if err != nil {
		return nil, err
	}
	threat.Name = name
	threat.Description = description
	threat.Severity = severity
	threat.Type = threatType
	threat.UpdatedAt = time.Now().UTC()
	if err := s.repository.Update(ctx, threat); err != nil {
		return nil, err
	}
	return threat, nil
}
