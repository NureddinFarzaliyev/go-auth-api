package auth

import (
	"sync"

	"golang.org/x/crypto/bcrypt"
)

type MemoryTaskRepository struct {
	memory []User
	mu     sync.Mutex
}

var _ AuthRepository = &MemoryTaskRepository{}

func NewAuthMemoryTaskRepository() *MemoryTaskRepository {
	return &MemoryTaskRepository{}
}

func (r *MemoryTaskRepository) Register(user User) error {
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
		return ErrorAlreadyRegistered
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		return ErrorInternal
	}

	newUser := User{
		Email:    user.Email,
		Password: string(hashedPassword),
	}

	r.memory = append(r.memory, newUser)
	return nil
}
