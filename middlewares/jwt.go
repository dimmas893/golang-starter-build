package middleware

import (
	"net/http"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/golang-jwt/jwt/v4"
	"github.com/jeypc/go-jwt-mux/config"
	"github.com/jeypc/go-jwt-mux/helper"
)

var blacklist = make(map[string]bool)
var mutex sync.Mutex

// JWTMiddleware adalah middleware untuk memvalidasi token JWT pada setiap permintaan
func JWTMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("signature")
		if tokenString == "" {
			helper.GenerateErrorResponse(w, helper.UNAUTHORIZED, "Token tidak ditemukan", nil)
			return
		}

		if IsBlacklisted(tokenString) {
			helper.GenerateErrorResponse(w, helper.UNAUTHORIZED, "Token tidak valid", nil)
			return
		}

		claims := &config.JWTClaim{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
			return config.JWT_KEY, nil
		})

		if err != nil {
			v, _ := err.(*jwt.ValidationError)
			switch v.Errors {
			case jwt.ValidationErrorSignatureInvalid:
				helper.GenerateErrorResponse(w, helper.UNAUTHORIZED, "Token tidak valid", nil)
				return
			case jwt.ValidationErrorExpired:
				helper.GenerateErrorResponse(w, helper.UNAUTHORIZED, "Token telah kadaluarsa", nil)
				return
			default:
				helper.GenerateErrorResponse(w, helper.UNAUTHORIZED, "Token tidak valid", nil)
				return
			}
		}

		if !token.Valid {
			helper.GenerateErrorResponse(w, helper.UNAUTHORIZED, "Token tidak valid", nil)
			return
		}

		newTokenString, err := helper.CreateJWTToken(claims.Username, 1*time.Minute)
		if err != nil {
			helper.GenerateErrorResponse(w, helper.SERVER_GENERAL_ERROR, "Token Creation Error", err.Error())
			return
		}

		w.Header().Set("signature", newTokenString)
		next.ServeHTTP(w, r)
	})
}

// IsBlacklisted memeriksa apakah token ada di Redis
func IsBlacklisted(token string) bool {
	result, err := config.RedisClient.Get(config.Ctx, token).Result()
	if err == redis.Nil {
		return false
	} else if err != nil {
		return false
	}
	return result == "blacklisted"
}

// AddToBlacklist menambahkan token ke Redis
func AddToBlacklist(token string, duration time.Duration) {
	err := config.RedisClient.Set(config.Ctx, token, "blacklisted", duration).Err()
	if err != nil {
		// Tangani kesalahan Redis di sini
	}
}
