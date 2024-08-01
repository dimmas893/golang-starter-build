package routes

import (
	"encoding/json"
	"net/http"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/jeypc/go-jwt-mux/helper"
)

// Response struct
type Response struct {
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
	Data    any    `json:"data,omitempty"`
}

// GenerateAsymmetricKeyHandler handles key generation
func GenerateAsymmetricKeyHandler(w http.ResponseWriter, r *http.Request) {
	privateKey, publicKey, err := helper.GenerateAsymmetricKey()
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to generate keys")
		return
	}

	uniqueName := r.FormValue("unique_name")
	if uniqueName == "" {
		uniqueName = uuid.NewString()
	}

	err = helper.SaveCredentials(privateKey, publicKey, uniqueName)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to save keys")
		return
	}

	respondWithJSON(w, http.StatusOK, map[string]string{
		"privateKey": privateKey,
		"publicKey":  publicKey,
		"uniqueName": uniqueName,
	})
}

// GenerateAccessTokenHandler handles JWT generation
func GenerateAccessTokenHandler(w http.ResponseWriter, r *http.Request) {
	subject := r.FormValue("subject")
	audience := r.FormValue("audience")
	token, err := helper.GenerateAccessToken(subject, audience, 3600) // 1 hour
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to generate token")
		return
	}

	respondWithJSON(w, http.StatusOK, map[string]string{
		"token": token,
	})
}

// VerifyAccessTokenHandler handles JWT verification
func VerifyAccessTokenHandler(w http.ResponseWriter, r *http.Request) {
	token := r.FormValue("token")
	claims, err := helper.VerifyAccessToken(token)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Invalid token")
		return
	}

	respondWithJSON(w, http.StatusOK, claims)
}

// Utility functions for responses
func respondWithError(w http.ResponseWriter, code int, message string) {
	respondWithJSON(w, code, Response{Status: "error", Message: message})
}

func respondWithJSON(w http.ResponseWriter, code int, payload any) {
	response, _ := json.Marshal(Response{Status: "success", Data: payload})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(response)
}

// SetupSecurityRoutes sets up security-related routes
func SetupSecurityRoutes(router *mux.Router) {
	router.HandleFunc("/generate-asymmetric-key", GenerateAsymmetricKeyHandler).Methods("POST")
	router.HandleFunc("/generate-access-token", GenerateAccessTokenHandler).Methods("POST")
	router.HandleFunc("/verify-access-token", VerifyAccessTokenHandler).Methods("POST")
}
