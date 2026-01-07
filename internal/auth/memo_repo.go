package auth

import (
	"context"
	"sync"
	"time"

	"github.com/NureddinFarzaliyev/go-auth-api/internal/httpx"
	"github.com/NureddinFarzaliyev/go-auth-api/internal/utils"
	"golang.org/x/crypto/bcrypt"
)

type MemoryAuthRepository struct {
	memory []User
	mu     sync.Mutex
}

var _ AuthRepository = &MemoryAuthRepository{}

func NewMemoryAuthRepository() *MemoryAuthRepository {
	return &MemoryAuthRepository{}
}

func (r *MemoryAuthRepository) IsValidSession(ctx context.Context, loginToken string, csrfToken string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	userIdx := -1
	for i, v := range r.memory {
		if v.Meta.SessionToken == loginToken && v.Meta.CsrfToken == csrfToken {
			userIdx = i
			break
		}
	}

	if userIdx == -1 {
		return "", httpx.ErrorNotAuthorized
	}

	now := time.Now()
	expires_at := r.memory[userIdx].Meta.ExpiresAt
	isExpired := now.After(expires_at)

	if isExpired {
		return "", httpx.ErrorNotAuthorized
	}

	email := r.memory[userIdx].Email

	return email, nil
}

func (r *MemoryAuthRepository) Register(ctx context.Context, user User) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	exists := false

	for _, val := range r.memory {
		if val.Email == user.Email {
			exists = true
			break
		}
	}

	if exists {
		return httpx.ErrorAlreadyRegistered
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		return httpx.ErrorInternal
	}

	newUser := User{
		Email:    user.Email,
		Password: string(hashedPassword),
	}

	r.memory = append(r.memory, newUser)
	return nil
}

func (r *MemoryAuthRepository) Login(ctx context.Context, user UserLogin) (token string, csrf string, expires time.Time, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	existingUserIdx := -1

	for i, v := range r.memory {
		if user.Email == v.Email {
			existingUserIdx = i
			break
		}
	}

	if existingUserIdx == -1 {
		return "", "", time.Time{}, httpx.ErrorUserNotFoundOrWrongCredentials
	}

	correctPass := bcrypt.CompareHashAndPassword([]byte(r.memory[existingUserIdx].Password), []byte(user.Password))
	if correctPass != nil {
		return "", "", time.Time{}, httpx.ErrorUserNotFoundOrWrongCredentials
	}

	loginToken, err := utils.GenerateToken()
	if err != nil {
		return "", "", time.Time{}, httpx.ErrorInternal
	}

	loginExpires := time.Now().Add(24 * time.Hour)

	r.memory[existingUserIdx].Meta.SessionToken = loginToken
	r.memory[existingUserIdx].Meta.ExpiresAt = loginExpires

	csrfToken, err := utils.GenerateToken()
	if err != nil {
		return "", "", time.Time{}, httpx.ErrorInternal
	}

	r.memory[existingUserIdx].Meta.CsrfToken = csrfToken

	return loginToken, csrfToken, loginExpires, nil
}

func (r *MemoryAuthRepository) Logout(ctx context.Context, email string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	userIdx := -1

	for i, v := range r.memory {
		if email == v.Email {
			userIdx = i
			break
		}
	}

	if userIdx == -1 {
		return httpx.ErrorInternal
	}

	user := &r.memory[userIdx]
	user.Meta.CsrfToken = ""
	user.Meta.SessionToken = ""
	user.Meta.ExpiresAt = time.Now()

	return nil
}
