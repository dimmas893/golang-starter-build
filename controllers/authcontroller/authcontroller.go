package authcontroller

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/jeypc/go-jwt-mux/config"
	"github.com/jeypc/go-jwt-mux/helper"
	middleware "github.com/jeypc/go-jwt-mux/middlewares"
	"github.com/jeypc/go-jwt-mux/models"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// Login adalah fungsi untuk proses login pengguna
func Login(w http.ResponseWriter, r *http.Request) {
	var userInput models.User

	// Decode JSON input dari request body
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&userInput); err != nil {
		// Jika ada error saat decode, kirim response error
		helper.GenerateErrorResponse(w, helper.INVALID_FIELD_FORMAT, err.Error(), nil)
		return
	}
	defer r.Body.Close()

	var user models.User

	// Cari user di database berdasarkan username
	if err := models.DB.Where("username = ?", userInput.Username).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			// Jika user tidak ditemukan
			helper.GenerateErrorResponse(w, helper.LOGIN_FAILED, err.Error(), nil)
			return
		}
		// Jika ada error lain saat akses database
		helper.GenerateErrorResponse(w, helper.SERVER_GENERAL_ERROR, err.Error(), nil)
		return
	}

	// Cek password yang diinput oleh user dengan password yang tersimpan di database
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(userInput.Password)); err != nil {
		// Jika password tidak cocok
		helper.GenerateErrorResponse(w, helper.LOGIN_FAILED, err.Error(), nil)
		return
	}

	// Buat token JWT untuk user yang valid
	token, err := helper.CreateJWTToken(user.Username, 1*time.Minute) // Menggunakan helper untuk membuat token dengan durasi 1 menit
	if err != nil {
		// Jika ada error saat membuat token
		helper.GenerateErrorResponse(w, helper.SERVER_GENERAL_ERROR, "Token generation error", err.Error())
		return
	}

	// Set token di cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Path:     "/",
		Value:    token,
		HttpOnly: true,
	})

	// Kirim response sukses dengan token yang dihasilkan
	helper.GenerateResponse(w, helper.OK, map[string]string{"token": token})
}

// Register adalah fungsi untuk proses registrasi pengguna baru
func Register(w http.ResponseWriter, r *http.Request) {
	var userInput models.User

	// Decode JSON input dari request body
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&userInput); err != nil {
		// Jika ada error saat decode, kirim response error
		helper.GenerateErrorResponse(w, helper.INVALID_FIELD_FORMAT, err.Error(), nil)
		return
	}
	defer r.Body.Close()

	var user models.User
	var err error // Deklarasikan err di sini

	// Cek apakah username sudah ada di database
	if err = models.DB.Where("username = ?", userInput.Username).First(&user).Error; err == nil {
		// Jika username sudah ada
		helper.GenerateErrorResponse(w, helper.INVALID_FIELD_FORMAT, "Username sudah ada", nil)
		return
	}

	// Jika ada error lain selain ErrRecordNotFound saat mengakses database
	if err != nil && err != gorm.ErrRecordNotFound {
		helper.GenerateErrorResponse(w, helper.SERVER_GENERAL_ERROR, err.Error(), nil)
		return
	}

	// Hash password sebelum disimpan ke database
	hashPassword, _ := bcrypt.GenerateFromPassword([]byte(userInput.Password), bcrypt.DefaultCost)
	userInput.Password = string(hashPassword)

	// Simpan user baru ke database
	if err = models.DB.Create(&userInput).Error; err != nil {
		// Jika ada error saat menyimpan user baru ke database
		helper.GenerateErrorResponse(w, helper.SERVER_GENERAL_ERROR, err.Error(), nil)
		return
	}

	// Kirim response sukses
	helper.GenerateResponse(w, helper.OK, nil)
}

// Logout adalah fungsi untuk proses logout pengguna
func Logout(w http.ResponseWriter, r *http.Request) {
	// Mengambil token dari header "signature"
	tokenString := r.Header.Get("signature")
	if tokenString == "" {
		// Jika signature tidak ditemukan, kirim respon
		helper.GenerateErrorResponse(w, helper.UNAUTHORIZED, "Token tidak ditemukan", nil)
		return
	}

	// Mem-parsing token untuk memvalidasi apakah token valid
	claims := &config.JWTClaim{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
		return config.JWT_KEY, nil
	})

	if err != nil || !token.Valid {
		// Jika token tidak valid atau ada kesalahan saat parsing token
		helper.GenerateErrorResponse(w, helper.UNAUTHORIZED, "Token tidak valid", nil)
		return
	}

	// Cek apakah token sudah ada di Redis
	if middleware.IsBlacklisted(tokenString) {
		helper.GenerateResponse(w, helper.OK, "Anda sudah logout")
		return
	}

	// Tambahkan token ke Redis dengan durasi yang cukup lama (misalnya 24 jam)
	middleware.AddToBlacklist(tokenString, 24*time.Hour)

	// Hapus token dari cookie dengan mengatur MaxAge menjadi -1
	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Path:     "/",
		Value:    "",
		HttpOnly: true,
		MaxAge:   -1,
	})

	// Kirim response sukses
	helper.GenerateResponse(w, helper.OK, "Logout berhasil")
}
