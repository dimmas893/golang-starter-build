package helper

import (
	"errors"
	"net/http"
)

// LogContext formats the context for logging
func LogContext(data interface{}) map[string]interface{} {
	switch v := data.(type) {
	case error:
		return map[string]interface{}{
			"error_class":   "error",
			"error_message": v.Error(),
		}
	case *http.Response:
		return map[string]interface{}{
			"response_status": v.StatusCode,
			"response_body":   v.Body,
		}
	case []map[string]interface{}:
		return map[string]interface{}{
			"response_data": v,
		}
	default:
		return map[string]interface{}{
			"unknown_type": errors.New("unknown data type"),
		}
	}
}
