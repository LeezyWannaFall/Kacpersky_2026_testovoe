package handler

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/LeezyWannaFall/Kacpersky_2026_testovoe/internal/model"
	"github.com/LeezyWannaFall/Kacpersky_2026_testovoe/internal/service"
	"github.com/go-chi/chi/v5"
)

const maxRequestBody = 1 << 20 // 1 MiB

type threatService interface {
	Create(rctx context.Context, md5, name, description string, severity model.Severity, threatType string) (*model.Threat, error)
	Get(rctx context.Context, md5 string) (*model.Threat, error)
	Update(rctx context.Context, md5, name, description string, severity model.Severity, threatType string) (*model.Threat, error)
}

type Handler struct {
	service threatService
}

func New(svc threatService) *Handler {
	return &Handler{service: svc}
}

func (h *Handler) Routes() http.Handler {
	r := chi.NewRouter()
	r.Get("/info/{md5}", h.get)
	r.Put("/info/{md5}", h.update)
	r.Post("/info", h.create)
	return r
}

type createRequest struct {
	MD5         string `json:"md5"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Type        string `json:"type"`
}

type updateRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Type        string `json:"type"`
}

type threatResponse struct {
	MD5         string `json:"md5"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Type        string `json:"type"`
	CreatedAt   string `json:"createdAt"`
	UpdatedAt   string `json:"updatedAt"`
}

type errorResponse struct {
	Message string `json:"message"`
	Details string `json:"details,omitempty"`
}

func (h *Handler) get(w http.ResponseWriter, r *http.Request) {
	md5 := chi.URLParam(r, "md5")
	threat, err := h.service.Get(r.Context(), md5)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toResponse(threat))
}

func (h *Handler) create(w http.ResponseWriter, r *http.Request) {
	var request createRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, err)
		return
	}
	if strings.TrimSpace(request.MD5) == "" || strings.TrimSpace(request.Name) == "" || request.Severity == "" {
		writeError(w, ErrInvalidRequest)
		return
	}

	threat, err := h.service.Create(r.Context(), request.MD5, request.Name, request.Description, model.Severity(request.Severity), request.Type)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, toResponse(threat))
}

func (h *Handler) update(w http.ResponseWriter, r *http.Request) {
	md5 := chi.URLParam(r, "md5")
	var request updateRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, err)
		return
	}
	if strings.TrimSpace(request.Name) == "" || request.Severity == "" {
		writeError(w, ErrInvalidRequest)
		return
	}

	threat, err := h.service.Update(r.Context(), md5, request.Name, request.Description, model.Severity(request.Severity), request.Type)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toResponse(threat))
}

var (
	ErrInvalidRequest  = errors.New("invalid request")
	ErrInvalidJSON     = errors.New("invalid JSON body")
	ErrRequestTooLarge = errors.New("request body is too large")
)

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			return ErrRequestTooLarge
		}
		return errors.Join(ErrInvalidJSON, err)
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		if err == nil {
			return ErrInvalidJSON
		}
		return errors.Join(ErrInvalidJSON, err)
	}
	return nil
}

func toResponse(threat *model.Threat) threatResponse {
	return threatResponse{
		MD5: threat.MD5, Name: threat.Name, Description: threat.Description,
		Severity: string(threat.Severity), Type: threat.Type,
		CreatedAt: threat.CreatedAt.UTC().Format(time.RFC3339Nano),
		UpdatedAt: threat.UpdatedAt.UTC().Format(time.RFC3339Nano),
	}
}

func writeError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	message := "internal server error"
	details := ""
	switch {
	case errors.Is(err, model.ErrInvalidMD5):
		status, message = http.StatusBadRequest, "invalid MD5"
	case errors.Is(err, model.ErrInvalidName), errors.Is(err, model.ErrInvalidSeverity), errors.Is(err, ErrInvalidRequest), errors.Is(err, ErrInvalidJSON):
		status, message = http.StatusBadRequest, "invalid request"
		details = err.Error()
	case errors.Is(err, ErrRequestTooLarge):
		status, message = http.StatusBadRequest, "request body is too large"
	case errors.Is(err, service.ErrNotFound):
		status, message = http.StatusNotFound, "threat not found"
	case errors.Is(err, service.ErrConflict):
		status, message = http.StatusConflict, "threat already exists"
	default:
	}
	writeJSON(w, status, errorResponse{Message: message, Details: details})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
