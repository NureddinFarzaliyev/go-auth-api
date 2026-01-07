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

	if err := h.repo.Register(r.Context(), user); err != nil {
		if err == httpx.ErrorAlreadyRegistered {
			httpx.Error(w, httpx.ErrorAlreadyRegistered.Error(), http.StatusConflict)
		} else {
			httpx.Error(w, httpx.ErrorInternal.Error(), http.StatusInternalServerError)
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

	token, csrf, expires, err := h.repo.Login(r.Context(), user)

	if err != nil {
		if err == httpx.ErrorUserNotFoundOrWrongCredentials {
			httpx.Error(w, httpx.ErrorUserNotFoundOrWrongCredentials.Error(), http.StatusBadRequest)
		} else {
			httpx.Error(w, httpx.ErrorInternal.Error(), http.StatusInternalServerError)
		}
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     CookieSessionToken,
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

func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	email := r.Context().Value(UserEmailContext).(string)
	if email == "" {
		httpx.Error(w, httpx.ErrorInternal.Error(), http.StatusInternalServerError)
		return
	}
	err := h.repo.Logout(r.Context(), email)
	if err != nil {
		httpx.Error(w, httpx.ErrorInternal.Error(), http.StatusInternalServerError)
		return
	}
	httpx.JSON(w, http.StatusOK, httpx.Envelope{})
}
