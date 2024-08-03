package routes

import (
	"github.com/gorilla/mux"
	"github.com/jeypc/go-jwt-mux/controllers/securitycontroller"
)

// Response struct
type Response struct {
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
	Data    any    `json:"data,omitempty"`
}

// SetupSecurityRoutes sets up security-related routes
func SetupSecurityRoutes(router *mux.Router) {
	router.HandleFunc("/generate-asymmetric-key", securitycontroller.GenerateAsymmetricKeyHandler).Methods("POST")
	router.HandleFunc("/generate-access-token", securitycontroller.GenerateAccessTokenHandler).Methods("POST")
	router.HandleFunc("/verify-access-token", securitycontroller.VerifyAccessTokenHandler).Methods("POST")
	router.HandleFunc("/get-credential", securitycontroller.GetCredentialsHandler).Methods("POST")
}
