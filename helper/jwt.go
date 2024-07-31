package helper

import (
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/jeypc/go-jwt-mux/config"
)

// CreateJWTToken generates a new JWT token with a specified duration
func CreateJWTToken(username string, duration time.Duration) (string, error) {
	expirationTime := time.Now().Add(duration)
	claims := &config.JWTClaim{
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "go-jwt-mux",
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(config.JWT_KEY)
}

// RefreshJWTToken refreshes the JWT token with a new duration
func RefreshJWTToken(tokenString string, duration time.Duration) (string, error) {
	claims := &config.JWTClaim{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
		return config.JWT_KEY, nil
	})
	if err != nil {
		return "", err
	}
	if !token.Valid {
		return "", jwt.ErrSignatureInvalid
	}

	expirationTime := time.Now().Add(duration)
	claims.ExpiresAt = jwt.NewNumericDate(expirationTime)
	newToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return newToken.SignedString(config.JWT_KEY)
}
