package auth

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/NureddinFarzaliyev/go-auth-api/internal/httpx"
)

type Handler struct {
	repo AuthRepository
}

func NewAuthHandler(repo AuthRepository) *Handler {
	return &Handler{repo: repo}
}

func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	var user User

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&user); err != nil {
		if err == io.EOF {
			httpx.Error(w, "Request body is required", http.StatusBadRequest)
		} else {
			httpx.Error(w, err.Error(), http.StatusBadRequest)
		}
		return
	}

	if err := h.repo.Register(user); err != nil {
		if err == ErrorAlreadyRegistered {
			httpx.Error(w, ErrorAlreadyRegistered.Error(), http.StatusConflict)
		} else {
			httpx.Error(w, "Unexpected error happened.", http.StatusInternalServerError)
		}
		return
	}

	httpx.JSON(w, http.StatusCreated, httpx.Envelope{})
}
