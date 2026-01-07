package auth

import (
	"context"
	"time"
)

type AuthRepository interface {
	Register(ctx context.Context, user User) error
	Login(ctx context.Context, user UserLogin) (token string, csrf string, expires time.Time, err error)
	Logout(ctx context.Context, email string) (err error)
	IsValidSession(ctx context.Context, loginToken string, csrfToken string) (string, error)
}
