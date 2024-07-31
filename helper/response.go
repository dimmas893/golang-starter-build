package helper

import (
	"encoding/json"
	"net/http"
)

// Response structure
type Response struct {
	Status  string      `json:"status"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// ErrorResponse structure
type ErrorResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
	Error   string `json:"error"`
}

// ResponseJSON sends a standard JSON response
func ResponseJSON(w http.ResponseWriter, code int, message string, data interface{}) {
	response := Response{
		Status:  "success",
		Message: message,
		Data:    data,
	}

	if code >= 400 {
		response.Status = "error"
	}

	jsonResponse, _ := json.Marshal(response)
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(jsonResponse)
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
