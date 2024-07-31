package helper

import (
	"encoding/json"
	"net/http"
)

// ErrorResponse structure
type ErrorResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
	Error   string `json:"error"`
}

// ResponseError sends a standard JSON error response
func ResponseError(w http.ResponseWriter, code int, message string, err string) {
	response := ErrorResponse{
		Status:  "error",
		Message: message,
		Error:   err,
	}

	jsonResponse, _ := json.Marshal(response)
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(jsonResponse)
}

// NotFound sends a 404 Not Found error response
func NotFound(w http.ResponseWriter, message string, err string) {
	ResponseError(w, http.StatusNotFound, message, err)
}

// BadRequest sends a 400 Bad Request error response
func BadRequest(w http.ResponseWriter, message string, err string) {
	ResponseError(w, http.StatusBadRequest, message, err)
}

// InternalServerError sends a 500 Internal Server Error response
func InternalServerError(w http.ResponseWriter, message string, err string) {
	ResponseError(w, http.StatusInternalServerError, message, err)
}

// Unauthorized sends a 401 Unauthorized error response
func Unauthorized(w http.ResponseWriter, message string, err string) {
	ResponseError(w, http.StatusUnauthorized, message, err)
}

// Forbidden sends a 403 Forbidden error response
func Forbidden(w http.ResponseWriter, message string, err string) {
	ResponseError(w, http.StatusForbidden, message, err)
}
