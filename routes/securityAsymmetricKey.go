package routes

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"path/filepath"

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

	secretKey := uuid.NewString() // Generate a unique secret key for demonstration

	savedSecret, err := helper.SaveCredentials(privateKey, publicKey, secretKey)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to save keys")
		return
	}

	respondWithJSON(w, http.StatusOK, map[string]string{
		"privateKey": privateKey,
		"publicKey":  publicKey,
		"secret":     savedSecret,
	})
}

func GenerateAccessTokenHandler(w http.ResponseWriter, r *http.Request) {
	apiKey := r.FormValue("apiKey")
	secret := r.FormValue("secret")
	privateKey := r.FormValue("privateKey")
	audience := r.FormValue("audience")

	if apiKey == "" || secret == "" || privateKey == "" || !helper.ValidateSecret(apiKey, secret, privateKey) {
		respondWithError(w, http.StatusUnauthorized, "Invalid apiKey, secret, or privateKey")
		return
	}

	token, err := helper.GenerateAccessToken(apiKey, secret, privateKey, audience, 3600) // 1 hour
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
func GetCredentialsHandler(w http.ResponseWriter, r *http.Request) {
	apiKey := r.FormValue("apiKey")

	// Tambahkan log untuk memeriksa nilai yang diterima
	log.Printf("Received apiKey: %s", apiKey)

	// Cek apakah folder ada
	folderPath := filepath.Join("logs", "credentials", apiKey)
	if _, err := os.Stat(folderPath); os.IsNotExist(err) {
		log.Printf("Folder does not exist: %s", folderPath)
		respondWithError(w, http.StatusInternalServerError, "Failed to get api key")
		return
	}

	// Baca secret.key
	secret, err := helper.GetCredential(apiKey, "secret.key")
	if err != nil {
		log.Printf("Error getting secret key: %v", err) // Log the error for debugging
		respondWithError(w, http.StatusInternalServerError, "Failed to get secret key")
		return
	}

	// Baca public.key
	publicKey, err := helper.GetCredential(apiKey, "public.key")
	if err != nil {
		log.Printf("Error getting public key: %v", err) // Log the error for debugging
		respondWithError(w, http.StatusInternalServerError, "Failed to get public key")
		return
	}

	// Baca private.key
	privateKey, err := helper.GetCredential(apiKey, "private.key")
	if err != nil {
		log.Printf("Error getting private key: %v", err) // Log the error for debugging
		respondWithError(w, http.StatusInternalServerError, "Failed to get private key")
		return
	}

	respondWithJSON(w, http.StatusOK, map[string]string{
		"secret":     secret,
		"publicKey":  publicKey,
		"privateKey": privateKey,
	})
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
	router.HandleFunc("/get-credential", GetCredentialsHandler).Methods("POST")
}
