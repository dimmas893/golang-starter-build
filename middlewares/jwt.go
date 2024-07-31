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
		// Mengambil token dari header "signature"
		tokenString := r.Header.Get("signature")
		if tokenString == "" {
			// Jika token tidak ditemukan, kirim respon Unauthorized
			helper.Unauthorized(w, "Unauthorized", "Token tidak ditemukan")
			return
		}

		// Memeriksa apakah token ada di Redis
		if IsBlacklisted(tokenString) {
			helper.Unauthorized(w, "Unauthorized", "Token tidak valid")
			return
		}

		claims := &config.JWTClaim{}

		// Mem-parsing token dan memvalidasi klaimnya
		token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
			return config.JWT_KEY, nil
		})

		if err != nil {
			// Jika ada error saat parsing token, periksa jenis errornya
			v, _ := err.(*jwt.ValidationError)
			switch v.Errors {
			case jwt.ValidationErrorSignatureInvalid:
				// Token tidak valid (signature tidak valid)
				helper.Unauthorized(w, "Unauthorized", "Token tidak valid")
				return
			case jwt.ValidationErrorExpired:
				// Token telah kadaluarsa
				helper.Unauthorized(w, "Unauthorized", "Token telah kadaluarsa")
				return
			default:
				// Token tidak valid untuk alasan lainnya
				helper.Unauthorized(w, "Unauthorized", "Token tidak valid")
				return
			}
		}

		if !token.Valid {
			// Jika token tidak valid
			helper.Unauthorized(w, "Unauthorized", "Token tidak valid")
			return
		}

		// Reset durasi token menggunakan helper
		newTokenString, err := helper.CreateJWTToken(claims.Username, 1*time.Minute)
		if err != nil {
			helper.InternalServerError(w, "Token Creation Error", err.Error())
			return
		}

		// Set header status token dan token baru
		w.Header().Set("signature", newTokenString) // Replace token lama dengan token baru di header signature

		next.ServeHTTP(w, r) // Lanjutkan ke handler berikutnya
	})
}

// IsBlacklisted memeriksa apakah token ada di Redis
func IsBlacklisted(token string) bool {
	result, err := config.RedisClient.Get(config.Ctx, token).Result()
	if err == redis.Nil {
		return false
	} else if err != nil {
		// Tangani kesalahan Redis di sini
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
