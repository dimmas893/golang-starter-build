package helper

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"

	"golang.org/x/crypto/bcrypt"
)

// GenerateRandomString generates a random string of the given length
func GenerateRandomString(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes)[:length], nil
}

// EncryptString encrypts a plaintext string using AES encryption
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
	fmt.Printf("Encrypted and encoded ciphertext: %s\n", encodedCiphertext) // Log for debugging
	return encodedCiphertext, nil
}

// DoubleEncryptString first encrypts the plaintext string, then encrypts the resulting ciphertext again
func DoubleEncryptString(plaintext string) (string, error) {
	// First encryption
	firstEncryption, err := EncryptString(plaintext)
	if err != nil {
		return "", err
	}

	// Second encryption
	secondEncryption, err := EncryptString(firstEncryption)
	if err != nil {
		return "", err
	}

	return secondEncryption, nil
}

// SaveCredentials saves the credentials to files in a directory named after the API key
// SaveCredentials saves the credentials to files in a directory named after the API key
func SaveCredentials(apiKey, privateKey, publicKey, secret string) error {
	// Create the directory for storing credentials
	dirPath := filepath.Join("logs", "credentials", apiKey)
	if err := os.MkdirAll(dirPath, os.ModePerm); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	privateKeyPath := filepath.Join(dirPath, "private.key")
	publicKeyPath := filepath.Join(dirPath, "public.key")
	secretKeyPath := filepath.Join(dirPath, "secret.key")

	hashedSecret, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash secret: %w", err)
	}

	err = SaveKeyToFile(privateKey, privateKeyPath)
	if err != nil {
		return fmt.Errorf("failed to save private key: %w", err)
	}

	err = SaveKeyToFile(publicKey, publicKeyPath)
	if err != nil {
		return fmt.Errorf("failed to save public key: %w", err)
	}

	err = SaveKeyToFile(string(hashedSecret), secretKeyPath)
	if err != nil {
		return fmt.Errorf("failed to save secret key: %w", err)
	}

	return nil
}

func SaveKeyToFile(key, path string) error {
	err := os.MkdirAll(filepath.Dir(path), os.ModePerm)
	if err != nil {
		return err
	}

	return ioutil.WriteFile(path, []byte(key), 0644)
}
