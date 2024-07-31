package helper

import (
	"encoding/json"
	"net/http"
)

// Response structure for success
type Response struct {
	Status  string      `json:"status"`
	Message string      `json:"message"`
	Items   interface{} `json:"items,omitempty"`
}

// ResponseJSON sends a standard JSON response
func ResponseJSON(w http.ResponseWriter, code int, message string, data interface{}) {
	response := Response{
		Status:  "success",
		Message: message,
		Items:   data,
	}

	jsonResponse, _ := json.Marshal(response)
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(jsonResponse)
}
