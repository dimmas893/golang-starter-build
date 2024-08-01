package middleware

import (
	"bytes"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/jeypc/go-jwt-mux/helper"
)

// LoggingMiddleware logs the details of each request and response
func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Log request details
		logRequest(r)

		// Capture the response
		rec := &responseRecorder{ResponseWriter: w, responseBody: &bytes.Buffer{}}
		next.ServeHTTP(rec, r)

		// Log response details
		logResponse(rec, start)
	})
}

func logRequest(r *http.Request) {
	bodyBytes, _ := ioutil.ReadAll(r.Body)
	r.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes)) // Restore the request body

	helper.Info(helper.LOGGING, "Request received", map[string]interface{}{
		"method":         r.Method,
		"url":            r.URL.String(),
		"headers":        r.Header,
		"body":           string(bodyBytes),
		"remote_addr":    r.RemoteAddr,
		"content_length": r.ContentLength,
	})
}

func logResponse(rec *responseRecorder, start time.Time) {
	duration := time.Since(start)

	helper.Info(helper.LOGGING, "Response sent", map[string]interface{}{
		"status_code": rec.statusCode,
		"headers":     rec.Header(),
		"body":        rec.responseBody.String(),
		"duration":    duration.Seconds(),
	})
}

// responseRecorder is a wrapper for http.ResponseWriter that captures the status code and response body
type responseRecorder struct {
	http.ResponseWriter
	statusCode   int
	responseBody *bytes.Buffer
}

func (rec *responseRecorder) WriteHeader(statusCode int) {
	rec.statusCode = statusCode
	rec.ResponseWriter.WriteHeader(statusCode)
}

func (rec *responseRecorder) Write(b []byte) (int, error) {
	rec.responseBody.Write(b)
	return rec.ResponseWriter.Write(b)
}
