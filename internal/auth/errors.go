package auth

import "errors"

var ErrorAlreadyRegistered = errors.New("This email is already registered.")
var ErrorInternal = errors.New("Internal Server Error")
