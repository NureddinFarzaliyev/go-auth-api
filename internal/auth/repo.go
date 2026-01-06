package auth

import "time"

type AuthRepository interface {
	Register(User) error
	Login(UserLogin) (token string, csrf string, expires time.Time, err error)
}
