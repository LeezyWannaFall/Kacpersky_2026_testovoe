package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/LeezyWannaFall/Kacpersky_2026_testovoe/internal/model"
	"github.com/LeezyWannaFall/Kacpersky_2026_testovoe/internal/service"
)

const handlerMD5 = "d41d8cd98f00b204e9800998ecf8427e"

type fakeService struct {
	threat *model.Threat
	err    error
}

func (s *fakeService) Create(_ context.Context, md5, name, description string, severity model.Severity, threatType string) (*model.Threat, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &model.Threat{MD5: md5, Name: name, Description: description, Severity: severity, Type: threatType, CreatedAt: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), UpdatedAt: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)}, nil
}

func (s *fakeService) Get(context.Context, string) (*model.Threat, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.threat, nil
}

func (s *fakeService) Update(_ context.Context, md5, name, description string, severity model.Severity, threatType string) (*model.Threat, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &model.Threat{MD5: md5, Name: name, Description: description, Severity: severity, Type: threatType}, nil
}

func TestCreateSuccess(t *testing.T) {
	request := `{"md5":"` + handlerMD5 + `","name":"Trojan","severity":"high"}`
	r := httptest.NewRequest(http.MethodPost, "/info", strings.NewReader(request))
	w := httptest.NewRecorder()
	New(&fakeService{}).Routes().ServeHTTP(w, r)
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d: %s", w.Code, http.StatusCreated, w.Body)
	}
	var response threatResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.MD5 != handlerMD5 || response.Severity != "high" || response.CreatedAt == "" {
		t.Fatalf("unexpected response: %+v", response)
	}
}

func TestGetMapsServiceErrors(t *testing.T) {
	for _, tt := range []struct {
		name string
		err  error
		want int
	}{{"invalid md5", model.ErrInvalidMD5, http.StatusBadRequest}, {"missing", service.ErrNotFound, http.StatusNotFound}, {"internal", errors.New("database unavailable"), http.StatusInternalServerError}} {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/info/invalid", nil)
			w := httptest.NewRecorder()
			New(&fakeService{err: tt.err}).Routes().ServeHTTP(w, r)
			if w.Code != tt.want {
				t.Fatalf("status = %d, want %d", w.Code, tt.want)
			}
			if w.Header().Get("Content-Type") != "application/json" {
				t.Fatalf("Content-Type = %q", w.Header().Get("Content-Type"))
			}
		})
	}
}

func TestCreateRejectsMalformedMissingAndOversizedBodies(t *testing.T) {
	for _, tt := range []struct {
		name string
		body string
	}{{"malformed", "{"}, {"missing required fields", `{"md5":"` + handlerMD5 + `"}`}, {"unknown field", `{"md5":"` + handlerMD5 + `","name":"x","severity":"low","extra":1}`}} {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/info", strings.NewReader(tt.body))
			w := httptest.NewRecorder()
			New(&fakeService{}).Routes().ServeHTTP(w, r)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d", w.Code, http.StatusBadRequest)
			}
		})
	}

	r := httptest.NewRequest(http.MethodPost, "/info", strings.NewReader(strings.Repeat("x", maxRequestBody+1)))
	w := httptest.NewRecorder()
	New(&fakeService{}).Routes().ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("oversized status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestCreateMapsConflict(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/info", strings.NewReader(`{"md5":"`+handlerMD5+`","name":"x","severity":"low"}`))
	w := httptest.NewRecorder()
	New(&fakeService{err: service.ErrConflict}).Routes().ServeHTTP(w, r)
	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusConflict)
	}
}
