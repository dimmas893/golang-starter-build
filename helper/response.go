package helper

import (
	"encoding/json"
	"net/http"
	"strconv"
)

// ErrorResponse structure for errors
type ErrorResponse struct {
	ResponseCode    string      `json:"response_code"`
	ResponseMessage string      `json:"response_message"`
	Error           string      `json:"error,omitempty"`
	Data            interface{} `json:"data,omitempty"`
}

// Response structure for success
type Response struct {
	ResponseCode    string      `json:"response_code"`
	ResponseMessage string      `json:"response_message"`
	Data            interface{} `json:"data,omitempty"`
}

// GenerateErrorResponse sends a standard JSON error response
func GenerateErrorResponse(w http.ResponseWriter, code ResponseCode, err string, data interface{}) {
	response := ErrorResponse{
		ResponseCode:    string(code),
		ResponseMessage: code.Message(),
		Error:           err,
		Data:            data,
	}

	jsonResponse, _ := json.Marshal(response)
	w.Header().Set("Content-Type", "application/json")
	// Set the status code in the header based on the first 3 digits of the response code
	statusCode, _ := strconv.Atoi(string(code)[:3])
	w.WriteHeader(statusCode)
	w.Write(jsonResponse)
}

// GenerateResponse sends a standard JSON response
func GenerateResponse(w http.ResponseWriter, code ResponseCode, data interface{}) {
	response := Response{
		ResponseCode:    string(code),
		ResponseMessage: code.Message(),
		Data:            data,
	}

	jsonResponse, _ := json.Marshal(response)
	w.Header().Set("Content-Type", "application/json")
	// Set the status code in the header based on the first 3 digits of the response code
	statusCode, _ := strconv.Atoi(string(code)[:3])
	w.WriteHeader(statusCode)
	w.Write(jsonResponse)
}
