package authcontroller

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/jeypc/go-jwt-mux/config"
	"github.com/jeypc/go-jwt-mux/helper"
	"github.com/jeypc/go-jwt-mux/models"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

func Login(w http.ResponseWriter, r *http.Request) {
	var userInput models.User
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&userInput); err != nil {
		helper.ResponseError(w, http.StatusBadRequest, "Invalid input", err.Error())
		return
	}
	defer r.Body.Close()

	var user models.User
	if err := models.DB.Where("username = ?", userInput.Username).First(&user).Error; err != nil {
		switch err {
		case gorm.ErrRecordNotFound:
			helper.ResponseError(w, http.StatusUnauthorized, "Invalid credentials", "Username or password is incorrect")
			return
		default:
			helper.ResponseError(w, http.StatusInternalServerError, "Database error", err.Error())
			return
		}
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(userInput.Password)); err != nil {
		helper.ResponseError(w, http.StatusUnauthorized, "Invalid credentials", "Username or password is incorrect")
		return
	}

	expTime := time.Now().Add(time.Minute * 1)
	claims := &config.JWTClaim{
		Username: user.Username,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "go-jwt-mux",
			ExpiresAt: jwt.NewNumericDate(expTime),
		},
	}

	tokenAlgo := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token, err := tokenAlgo.SignedString(config.JWT_KEY)
	if err != nil {
		helper.ResponseError(w, http.StatusInternalServerError, "Token generation error", err.Error())
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Path:     "/",
		Value:    token,
		HttpOnly: true,
	})

	helper.ResponseJSON(w, http.StatusOK, "Login successful", map[string]string{"token": token})
}

func Register(w http.ResponseWriter, r *http.Request) {
	var userInput models.User
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&userInput); err != nil {
		helper.ResponseError(w, http.StatusBadRequest, "Invalid input", err.Error())
		return
	}
	defer r.Body.Close()

	hashPassword, _ := bcrypt.GenerateFromPassword([]byte(userInput.Password), bcrypt.DefaultCost)
	userInput.Password = string(hashPassword)

	if err := models.DB.Create(&userInput).Error; err != nil {
		helper.ResponseError(w, http.StatusInternalServerError, "Database error", err.Error())
		return
	}

	helper.ResponseJSON(w, http.StatusOK, "Registration successful", nil)
}

func Logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Path:     "/",
		Value:    "",
		HttpOnly: true,
		MaxAge:   -1,
	})

	helper.ResponseJSON(w, http.StatusOK, "Logout successful", nil)
}
