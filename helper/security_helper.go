package helper

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
)

// GenerateAsymmetricKey generates RSA key pair
func GenerateAsymmetricKey() (privateKey string, publicKey string, err error) {
	privateKeyObj, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKeyObj)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKeyObj.PublicKey)
	if err != nil {
		return "", "", err
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	return string(privateKeyPEM), string(publicKeyPEM), nil
}

// GetPublicKey extracts the public key from a private key
func GetPublicKey(privateKey string) (string, error) {
	block, _ := pem.Decode([]byte(privateKey))
	if block == nil {
		return "", errors.New("failed to parse PEM block containing the key")
	}

	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return "", err
	}

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return "", err
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	return string(publicKeyPEM), nil
}

// GenerateAsymmetricSignature signs data using RSA private key
func GenerateAsymmetricSignature(data, privateKey string) (string, error) {
	block, _ := pem.Decode([]byte(privateKey))
	if block == nil {
		return "", errors.New("failed to parse PEM block containing the key")
	}

	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return "", err
	}

	hashed := sha256.Sum256([]byte(data))
	signature, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, hashed[:])
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(signature), nil
}

// VerifyAsymmetricSignature verifies the RSA signature
func VerifyAsymmetricSignature(data, signature, publicKey string) (bool, error) {
	block, _ := pem.Decode([]byte(publicKey))
	if block == nil {
		return false, errors.New("failed to parse PEM block containing the key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return false, err
	}

	hashed := sha256.Sum256([]byte(data))
	sig, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false, err
	}

	err = rsa.VerifyPKCS1v15(pub.(*rsa.PublicKey), crypto.SHA256, hashed[:], sig)
	return err == nil, err
}

// GenerateSymmetricSignature generates a HMAC signature
func GenerateSymmetricSignature(data, key string) string {
	mac := hmac.New(sha512.New, []byte(key))
	mac.Write([]byte(data))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// VerifySymmetricSignature verifies a HMAC signature
func VerifySymmetricSignature(data, key, signature string) bool {
	expectedSignature := GenerateSymmetricSignature(data, key)
	return hmac.Equal([]byte(expectedSignature), []byte(signature))
}

// SaveKeyToFile saves a key to a specified file
func SaveKeyToFile(key, path string) error {
	err := os.MkdirAll(filepath.Dir(path), os.ModePerm)
	if err != nil {
		return err
	}

	return ioutil.WriteFile(path, []byte(key), 0644)
}

// SaveCredentials saves the private and public keys to respective files
func SaveCredentials(privateKey, publicKey, uniqueName string) error {
	privateKeyPath := filepath.Join("logs", "credentials", uniqueName, "private.key")
	publicKeyPath := filepath.Join("logs", "credentials", uniqueName, "public.key")

	err := SaveKeyToFile(privateKey, privateKeyPath)
	if err != nil {
		return err
	}

	return SaveKeyToFile(publicKey, publicKeyPath)
}

// GenerateAccessToken generates a JWT token
func GenerateAccessToken(subject, audience string, lifetime int) (string, error) {
	now := time.Now()
	claims := jwt.StandardClaims{
		Issuer:    "your_app_url",
		Subject:   subject,
		Audience:  audience,
		ExpiresAt: now.Add(time.Duration(lifetime) * time.Second).Unix(),
		NotBefore: now.Unix(),
		IssuedAt:  now.Unix(),
		Id:        uuid.NewString(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(os.Getenv("JWT_KEY")))
}

// VerifyAccessToken verifies a JWT token
func VerifyAccessToken(tokenStr string) (*jwt.StandardClaims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("JWT_KEY")), nil
	})
	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*jwt.StandardClaims); ok && token.Valid {
		return claims, nil
	} else {
		return nil, errors.New("invalid token")
	}
}

// StoreCredential stores an encrypted credential in a file
func StoreCredential(subject, filename, content, apiKey string) error {
	encryptedContent, err := EncryptString(content)
	if err != nil {
		return err
	}

	path := filepath.Join("credentials", subject, apiKey, filename)
	return ioutil.WriteFile(path, []byte(encryptedContent), 0644)
}

// GetCredential retrieves and decrypts a credential from a file
func GetCredential(subject, filename, apiKey string) (string, error) {
	path := filepath.Join("credentials", subject, apiKey, filename)
	encryptedContent, err := ioutil.ReadFile(path)
	if err != nil {
		return "", err
	}

	return DecryptString(string(encryptedContent))
}

// EncryptString encrypts a string
func EncryptString(plaintext string) (string, error) {
	key := []byte(os.Getenv("ENCRYPTION_KEY"))
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptString decrypts a string
func DecryptString(ciphertext string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	key := []byte(os.Getenv("ENCRYPTION_KEY"))
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, encryptedData := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, encryptedData, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}
