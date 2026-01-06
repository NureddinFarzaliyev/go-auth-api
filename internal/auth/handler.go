package auth

import (
	"encoding/json"
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
		httpx.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := h.repo.Register(user); err != nil {
		if err == ErrorAlreadyRegistered {
			httpx.Error(w, ErrorAlreadyRegistered.Error(), http.StatusConflict)
		} else {
			httpx.Error(w, ErrorInternal.Error(), http.StatusInternalServerError)
		}
		return
	}

	httpx.JSON(w, http.StatusCreated, httpx.Envelope{})
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var user UserLogin

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&user); err != nil {
		httpx.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	token, csrf, expires, err := h.repo.Login(user)

	if err != nil {
		if err == ErrorUserNotFoundOrWrongCredentials {
			httpx.Error(w, ErrorUserNotFoundOrWrongCredentials.Error(), http.StatusBadRequest)
		} else {
			httpx.Error(w, ErrorInternal.Error(), http.StatusInternalServerError)
		}
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    token,
		Expires:  expires,
		Path:     "/",
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
	})

	data := httpx.Envelope{
		"csrf":    csrf,
		"expires": expires,
	}

	httpx.JSON(w, http.StatusOK, data)
}
