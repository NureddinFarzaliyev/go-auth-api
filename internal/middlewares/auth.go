package middlewares

import (
	"net/http"

	"github.com/NureddinFarzaliyev/go-auth-api/internal/auth"
	"github.com/NureddinFarzaliyev/go-auth-api/internal/httpx"
)

type AuthMiddleware struct {
	repo auth.AuthRepository
}

func NewAuthMiddleware(repo auth.AuthRepository) *AuthMiddleware {
	return &AuthMiddleware{repo: repo}
}

func (m *AuthMiddleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(auth.CookieSessionToken)
		if err != nil {
			httpx.Error(w, "Unauthorized", http.StatusUnauthorized)
		}
		csrf := r.Header.Get("X-CSRF-TOKEN")
		uErr := m.repo.IsValidSession(cookie.Value, csrf)
		if uErr != nil {
			httpx.Error(w, "Unauthorized", http.StatusUnauthorized)
		}
	})
}
