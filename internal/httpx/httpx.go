package httpx

import (
	"encoding/json"
	"net/http"
)

type ErrorResponse struct {
	Message string `json:"message"`
	Status  int    `json:"status"`
}

type Envelope map[string]any

func JSON(w http.ResponseWriter, status int, data Envelope) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func Error(w http.ResponseWriter, message string, status int) {
	JSON(
		w,
		status,
		Envelope{"error": ErrorResponse{Message: message, Status: status}})
}
