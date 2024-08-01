package helper

import (
	"errors"
	"net/http"
)

func LogContext(data interface{}) map[string]interface{} {
	if err, ok := data.(error); ok {
		return map[string]interface{}{
			"error_class":   "error",
			"error_message": err.Error(),
		}
	}

	if resp, ok := data.(*http.Response); ok {
		return map[string]interface{}{
			"response_status": resp.StatusCode,
			"response_body":   resp.Body,
		}
	}

	return map[string]interface{}{
		"unknown_type": errors.New("unknown data type"),
	}
}
