package securitycontroller

import (
	"log"
	"net/http"

	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/jeypc/go-jwt-mux/helper"
	"github.com/jeypc/go-jwt-mux/models"
)

// Validator instance
var validate = validator.New()

func GenerateAccessTokenHandler(w http.ResponseWriter, r *http.Request) {
	apiKey := r.FormValue("apiKey")
	secret := r.FormValue("secret")
	privateKey := r.FormValue("privateKey")
	audience := r.FormValue("audience")

	if apiKey == "" || secret == "" || privateKey == "" || !helper.ValidateSecret(apiKey, secret, privateKey) {
		helper.GenerateErrorResponse(w, helper.UNAUTHORIZED, "Invalid apiKey, secret, or privateKey", nil)
		return
	}

	token, err := helper.GenerateAccessToken(apiKey, secret, privateKey, audience, 3600) // 1 hour
	if err != nil {
		helper.GenerateErrorResponse(w, helper.SERVER_GENERAL_ERROR, "Failed to generate token", nil)
		return
	}

	helper.GenerateResponse(w, helper.OK, map[string]string{
		"token": token,
	})
}

func GenerateAsymmetricKeyHandler(w http.ResponseWriter, r *http.Request) {
	privateKey, publicKey, err := helper.GenerateAsymmetricKey()
	if err != nil {
		helper.GenerateErrorResponse(w, helper.SERVER_GENERAL_ERROR, "Failed to generate keys: "+err.Error(), nil)
		return
	}

	apiKey := uuid.NewString() // Generate a unique API key

	// Generate a random 20-character secret key
	secretKey, err := helper.GenerateRandomString(20)
	if err != nil {
		helper.GenerateErrorResponse(w, helper.SERVER_GENERAL_ERROR, "Failed to generate secret key: "+err.Error(), nil)
		return
	}

	// Perform double encryption on the secret key
	encryptedSecretKey, err := helper.DoubleEncryptString(secretKey)
	if err != nil {
		helper.GenerateErrorResponse(w, helper.SERVER_GENERAL_ERROR, "Failed to encrypt secret key: "+err.Error(), nil)
		return
	}

	// Save the credentials to the database and file system
	err = helper.SaveCredentials(apiKey, privateKey, publicKey, secretKey)
	if err != nil {
		helper.GenerateErrorResponse(w, helper.SERVER_GENERAL_ERROR, "Failed to save credentials: "+err.Error(), nil)
		return
	}

	// Save the credentials to the database
	securityKey := models.SecurityAsymmetricKey{
		APIKey:     apiKey,
		PrivateKey: privateKey,
		PublicKey:  publicKey,
		Secret:     encryptedSecretKey,
	}

	// Validate the securityKey struct
	if err := validate.Struct(securityKey); err != nil {
		helper.GenerateErrorResponse(w, helper.INVALID_FIELD_FORMAT, "Validation failed: "+err.Error(), nil)
		return
	}

	if err := models.DB.Create(&securityKey).Error; err != nil {
		helper.GenerateErrorResponse(w, helper.SERVER_GENERAL_ERROR, "Failed to save credentials to database: "+err.Error(), nil)
		return
	}

	helper.GenerateResponse(w, helper.OK, map[string]string{
		"privateKey": privateKey,
		"publicKey":  publicKey,
		"secret":     encryptedSecretKey,
	})
}

// VerifyAccessTokenHandler handles JWT verification
func VerifyAccessTokenHandler(w http.ResponseWriter, r *http.Request) {
	token := r.FormValue("token")
	claims, err := helper.VerifyAccessToken(token)
	if err != nil {
		helper.GenerateErrorResponse(w, helper.UNAUTHORIZED, "Invalid token", nil)
		return
	}

	helper.GenerateResponse(w, helper.OK, claims)
}

func GetCredentialsHandler(w http.ResponseWriter, r *http.Request) {
	apiKey := r.FormValue("apiKey")

	// Tambahkan log untuk memeriksa nilai yang diterima
	log.Printf("Received apiKey: %s", apiKey)

	// Retrieve the credentials from the database
	var securityKey models.SecurityAsymmetricKey
	if err := models.DB.Where("api_key = ?", apiKey).First(&securityKey).Error; err != nil {
		helper.GenerateErrorResponse(w, helper.SERVER_GENERAL_ERROR, "Failed to get API key", nil)
		return
	}

	helper.GenerateResponse(w, helper.OK, map[string]string{
		"secret":     securityKey.Secret,
		"publicKey":  securityKey.PublicKey,
		"privateKey": securityKey.PrivateKey,
	})
}
