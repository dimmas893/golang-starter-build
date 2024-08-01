package userRequest

import (
	"strconv"
	"time"

	"github.com/jeypc/go-jwt-mux/models"
)

// ValidateNamaLengkap validates if the given nama_lengkap exists in the database
func ValidateNamaLengkap(namaLengkap string) error {
	if namaLengkap != "" { // Check if nama_lengkap is not empty
		var count int64
		// Query the database to check if nama_lengkap exists
		if err := models.DB.Model(&models.User{}).Where("nama_lengkap = ?", namaLengkap).Count(&count).Error; err != nil {
			return err // Return the error if the query fails
		}
		if count == 0 {
			// If no records are found, return a validation error
			return NewValidationError("Nama lengkap tidak ditemukan di database")
		}
	}
	return nil // Return nil if validation passes
}

// ValidateUsername validates if the given username exists in the database
func ValidateUsername(username string) error {
	if username != "" { // Check if username is not empty
		var count int64
		// Query the database to check if username exists
		if err := models.DB.Model(&models.User{}).Where("username = ?", username).Count(&count).Error; err != nil {
			return err // Return the error if the query fails
		}
		if count == 0 {
			// If no records are found, return a validation error
			return NewValidationError("Username tidak ditemukan di database")
		}
	}
	return nil // Return nil if validation passes
}

// ValidateDates validates if the given start_date and end_date are in the correct format
func ValidateDates(startDate, endDate, dateFormat string) error {
	if startDate != "" {
		// Check if start_date is in the correct format
		if _, err := time.Parse(dateFormat, startDate); err != nil {
			return NewValidationError("Start date format tidak valid")
		}
	}
	if endDate != "" {
		// Check if end_date is in the correct format
		if _, err := time.Parse(dateFormat, endDate); err != nil {
			return NewValidationError("End date format tidak valid")
		}
	}
	return nil // Return nil if validation passes
}

// ValidatePagination validates if the given per_page and page are positive integers
func ValidatePagination(perPage, page string) error {
	if perPage != "" {
		// Check if per_page is a positive integer
		if _, err := strconv.Atoi(perPage); err != nil {
			return NewValidationError("Per page harus berupa angka positif")
		}
	}
	if page != "" {
		// Check if page is a positive integer
		if _, err := strconv.Atoi(page); err != nil {
			return NewValidationError("Page harus berupa angka positif")
		}
	}
	return nil // Return nil if validation passes
}

// ValidationError represents a validation error
type ValidationError struct {
	Message string `json:"message"`
}

// NewValidationError creates a new validation error
func NewValidationError(message string) *ValidationError {
	return &ValidationError{Message: message}
}

// Error implements the error interface for ValidationError
func (e *ValidationError) Error() string {
	return e.Message
}
