package httpx

import "errors"

// General Errors
var ErrorNotAuthorized = errors.New("User is not authorized")
var ErrorInternal = errors.New("Internal Server Error")

// Auth Errors
var ErrorAlreadyRegistered = errors.New("This email is already registered.")
var ErrorUserNotFoundOrWrongCredentials = errors.New("User does not exist or credentials are wrong.")
