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
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
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

func HashSecret(secret string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func SaveKeyToFile(key, path string) error {
	err := os.MkdirAll(filepath.Dir(path), os.ModePerm)
	if err != nil {
		return err
	}

	return ioutil.WriteFile(path, []byte(key), 0644)
}
func SaveCredentials(privateKey, publicKey, secret string) (string, error) {
	privateKeyPath := filepath.Join("logs", "credentials", secret, "private.key")
	publicKeyPath := filepath.Join("logs", "credentials", secret, "public.key")
	secretKeyPath := filepath.Join("logs", "credentials", secret, "secret.key")

	hashedSecret, err := HashSecret(secret)
	if err != nil {
		return "", err
	}

	err = SaveKeyToFile(privateKey, privateKeyPath)
	if err != nil {
		return "", err
	}

	err = SaveKeyToFile(publicKey, publicKeyPath)
	if err != nil {
		return "", err
	}

	err = SaveKeyToFile(hashedSecret, secretKeyPath)
	if err != nil {
		return "", err
	}

	return hashedSecret, nil
}

// GenerateAccessToken generates a JWT token with the secret included as a claim
func GenerateAccessToken(apiKey, secret, privateKey, audience string, lifetime int) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"iss":        apiKey,
		"aud":        audience,
		"exp":        now.Add(time.Duration(lifetime) * time.Second).Unix(),
		"nbf":        now.Unix(),
		"iat":        now.Unix(),
		"jti":        uuid.NewString(),
		"secret":     secret,     // Include the secret in the claims
		"privateKey": privateKey, // Include the privateKey in the claims
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

func ValidateSecret(apiKey, secret, privateKey string) bool {
	// Membuat path lengkap untuk file secret.key dan private.key berdasarkan apiKey yang diberikan
	secretKeyPath := filepath.Join("logs", "credentials", apiKey, "secret.key")
	privateKeyPath := filepath.Join("logs", "credentials", apiKey, "private.key")

	// Log path untuk debug
	fmt.Printf("Secret key path: %s\n", secretKeyPath)
	fmt.Printf("Private key path: %s\n", privateKeyPath)

	// Membaca konten dari file secret.key
	storedSecret, err := ioutil.ReadFile(secretKeyPath)
	if err != nil {
		// Log error untuk debug
		fmt.Printf("Error reading secret key file: %v\n", err)
		// Jika terjadi kesalahan saat membaca file, kembalikan false
		return false
	}

	// Membaca konten dari file private.key
	storedPrivateKey, err := ioutil.ReadFile(privateKeyPath)
	if err != nil {
		// Log error untuk debug
		fmt.Printf("Error reading private key file: %v\n", err)
		// Jika terjadi kesalahan saat membaca file, kembalikan false
		return false
	}

	// Log secret yang tersimpan untuk debug
	fmt.Printf("Stored secret: %s\n", storedSecret)
	// Log private key yang tersimpan untuk debug
	fmt.Printf("Stored private key: %s\n", storedPrivateKey)
	// Log secret dan private key yang diberikan untuk debug
	fmt.Printf("Provided secret: %s\n", secret)
	fmt.Printf("Provided private key: %s\n", privateKey)

	// Cek jika storedSecret dan providedSecret sama secara langsung
	if string(storedSecret) == secret && string(storedPrivateKey) == privateKey {
		// Jika sama, lanjutkan validasi dengan bcrypt
		fmt.Println("Secrets and private key are directly equal, skipping bcrypt comparison.")
		return true
	}

	// Membandingkan secret yang diberikan dengan secret yang tersimpan menggunakan bcrypt
	// bcrypt.CompareHashAndPassword mengembalikan nil jika secret cocok
	err = bcrypt.CompareHashAndPassword(storedSecret, []byte(secret))
	if err != nil {
		// Log error untuk debug
		fmt.Printf("Error comparing secret: %v\n", err)
		// Jika secret tidak cocok, kembalikan false
		return false
	}

	// Membandingkan private key yang diberikan dengan private key yang tersimpan menggunakan bcrypt
	err = bcrypt.CompareHashAndPassword(storedPrivateKey, []byte(privateKey))
	if err != nil {
		// Log error untuk debug
		fmt.Printf("Error comparing private key: %v\n", err)
		// Jika private key tidak cocok, kembalikan false
		return false
	}

	// Jika secret dan private key cocok, kembalikan true
	return true
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

func GetCredential(apiKey, filename string) (string, error) {
	// Bangun path file credential
	path := filepath.Join("logs", "credentials", apiKey, filename)

	// Tambahkan log untuk memeriksa path file yang sedang dibaca
	fmt.Printf("Reading credential from path: %s\n", path)

	// Membaca konten dari file
	content, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to read file: %w", err)
	}

	return string(content), nil
}

func EncryptString(plaintext string) (string, error) {
	key := []byte(os.Getenv("ENCRYPTION_KEY"))
	if len(key) != 32 {
		return "", errors.New("encryption key must be 32 bytes long")
	}

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
	encodedCiphertext := base64.StdEncoding.EncodeToString(ciphertext)
	fmt.Printf("Encrypted and encoded ciphertext: %s\n", encodedCiphertext) // Log untuk debug
	return encodedCiphertext, nil
}

func DecryptString(ciphertext string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64: %w", err) // Menambahkan informasi error yang lebih jelas
	}

	key := []byte(os.Getenv("ENCRYPTION_KEY"))
	if len(key) != 32 {
		return "", errors.New("encryption key must be 32 bytes long")
	}

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
