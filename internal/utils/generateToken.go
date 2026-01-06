package utils

import (
	"crypto/rand"
	"encoding/base64"
)

func GenerateToken() (string, error) {
	b := make([]byte, 32) // 256-bit token
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
