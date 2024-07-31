package middlewares

import (
	"net/http"

	"github.com/golang-jwt/jwt/v4"
	"github.com/jeypc/go-jwt-mux/config"
	"github.com/jeypc/go-jwt-mux/helper"
)

func JWTMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("token")
		if err != nil {
			if err == http.ErrNoCookie {
				helper.ResponseError(w, http.StatusUnauthorized, "Unauthorized", "Token tidak ditemukan")
				return
			}
			helper.ResponseError(w, http.StatusInternalServerError, "Cookie Error", err.Error())
			return
		}

		tokenString := c.Value
		claims := &config.JWTClaim{}

		token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
			return config.JWT_KEY, nil
		})

		if err != nil {
			v, _ := err.(*jwt.ValidationError)
			switch v.Errors {
			case jwt.ValidationErrorSignatureInvalid:
				helper.ResponseError(w, http.StatusUnauthorized, "Unauthorized", "Token tidak valid")
				return
			case jwt.ValidationErrorExpired:
				helper.ResponseError(w, http.StatusUnauthorized, "Unauthorized", "Token telah kadaluarsa")
				return
			default:
				helper.ResponseError(w, http.StatusUnauthorized, "Unauthorized", "Token tidak valid")
				return
			}
		}

		if !token.Valid {
			helper.ResponseError(w, http.StatusUnauthorized, "Unauthorized", "Token tidak valid")
			return
		}

		next.ServeHTTP(w, r)
	})
}
