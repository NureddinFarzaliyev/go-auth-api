package auth

import (
	"time"
)

type UserMeta struct {
	SessionToken string    `bson:"session_token" json:"session_token"`
	ExpiresAt    time.Time `bson:"expires_at" json:"expires_at"`
	CsrfToken    string    `bson:"csrf_token" json:"csrf_token"`
}

type User struct {
	Email    string   `bson:"email" json:"email"`
	Password string   `bson:"password" json:"password"`
	Meta     UserMeta `bson:"meta" json:"meta"`
}

type UserLogin struct {
	Email    string
	Password string
}

var CookieSessionToken = "session_token"

var UserEmailContext = "userEmail"
