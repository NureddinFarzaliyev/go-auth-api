package auth

import (
	"time"
)

type UserMeta struct {
	session_token string
	expires_at    time.Time
	csrf_token    string
}

type User struct {
	Email    string
	Password string
	Meta     UserMeta
}

type UserLogin struct {
	Email    string
	Password string
}
