package usercontroller

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
	"github.com/jeypc/go-jwt-mux/helper"
	"github.com/jeypc/go-jwt-mux/models"
	"github.com/jeypc/go-jwt-mux/request/userRequest"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

func GetUsers(w http.ResponseWriter, r *http.Request) {
	var (
		users         []models.User
		totalRecords  int64
		namaLengkap   = r.URL.Query().Get("nama_lengkap")
		username      = r.URL.Query().Get("username")
		startDate     = r.URL.Query().Get("start_date")
		endDate       = r.URL.Query().Get("end_date")
		searchQuery   = r.URL.Query().Get("search_query")
		searchBy      = r.URL.Query().Get("search_by")
		sortBy        = r.URL.Query().Get("sort_by")
		sortDirection = r.URL.Query().Get("sort_direction")
		perPageStr    = r.URL.Query().Get("per_page")
		pageStr       = r.URL.Query().Get("page")
		perPage, _    = strconv.Atoi(perPageStr)
		page, _       = strconv.Atoi(pageStr)
		dateFormat    = r.URL.Query().Get("date_format") // Get date format from request
	)

	// Set default values if not provided
	if sortBy == "" {
		sortBy = "id"
	}
	if sortDirection == "" {
		sortDirection = "asc"
	}
	if perPage == 0 {
		perPage = 10
	}
	if page == 0 {
		page = 1
	}
	if dateFormat == "" {
		dateFormat = "2006-01-02" // Set default date format if not provided
	}

	// Validate all fields
	if err := userRequest.ValidateNamaLengkap(namaLengkap); err != nil {
		validationErr, ok := err.(*userRequest.ValidationError)
		if ok {
			// Return validation error response if validation fails
			helper.GenerateErrorResponse(w, helper.INVALID_FIELD_FORMAT, validationErr.Message, nil)
		} else {
			// Return server error response if there is a database error
			helper.GenerateErrorResponse(w, helper.SERVER_GENERAL_ERROR, "Database error", err.Error())
		}
		return
	}
	if err := userRequest.ValidateUsername(username); err != nil {
		validationErr, ok := err.(*userRequest.ValidationError)
		if ok {
			// Return validation error response if validation fails
			helper.GenerateErrorResponse(w, helper.INVALID_FIELD_FORMAT, validationErr.Message, nil)
		} else {
			// Return server error response if there is a database error
			helper.GenerateErrorResponse(w, helper.SERVER_GENERAL_ERROR, "Database error", err.Error())
		}
		return
	}
	if err := userRequest.ValidateDates(startDate, endDate, dateFormat); err != nil {
		validationErr, ok := err.(*userRequest.ValidationError)
		if ok {
			// Return validation error response if validation fails
			helper.GenerateErrorResponse(w, helper.INVALID_FIELD_FORMAT, validationErr.Message, nil)
		} else {
			// Return server error response if there is a database error
			helper.GenerateErrorResponse(w, helper.SERVER_GENERAL_ERROR, "Database error", err.Error())
		}
		return
	}
	if err := userRequest.ValidatePagination(perPageStr, pageStr); err != nil {
		validationErr, ok := err.(*userRequest.ValidationError)
		if ok {
			// Return validation error response if validation fails
			helper.GenerateErrorResponse(w, helper.INVALID_FIELD_FORMAT, validationErr.Message, nil)
		} else {
			// Return server error response if there is a database error
			helper.GenerateErrorResponse(w, helper.SERVER_GENERAL_ERROR, "Database error", err.Error())
		}
		return
	}

	query := models.DB.Model(&models.User{})

	// Apply filters based on request parameters
	if namaLengkap != "" {
		query = query.Where("nama_lengkap = ?", namaLengkap)
	}
	if username != "" {
		query = query.Where("username = ?", username)
	}
	if startDate != "" && endDate != "" {
		query = query.Where("created_at BETWEEN ? AND ?", startDate, endDate)
	}
	if searchQuery != "" && searchBy != "" {
		query = query.Where(searchBy+" LIKE ?", "%"+searchQuery+"%")
	}

	// Count the total number of records that match the filter criteria
	query.Count(&totalRecords)

	// Apply pagination and sorting
	query = query.Order(sortBy + " " + sortDirection).
		Limit(perPage).
		Offset((page - 1) * perPage).
		Find(&users)

	if query.Error != nil {
		// Return server error response if there is a database error
		helper.GenerateErrorResponse(w, helper.SERVER_GENERAL_ERROR, "Database error", query.Error.Error())
		return
	}

	// Convert users to []map[string]interface{} for pagination response
	data := []map[string]interface{}{}
	for _, user := range users {
		data = append(data, map[string]interface{}{
			"id":           user.Id,
			"nama_lengkap": user.NamaLengkap,
			"username":     user.Username,
			"password":     user.Password,
		})
	}

	// Create pagination response
	pagination := helper.CreatePagination(r, data, perPage, totalRecords)

	// Return successful paginated response
	helper.ResponsePaginatedJSON(w, helper.OK, "Data users berhasil diambil", pagination)
}

// CreateUser handles creating a new user
func CreateUser(w http.ResponseWriter, r *http.Request) {
	var userInput models.User
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&userInput); err != nil {
		helper.GenerateErrorResponse(w, helper.INVALID_FIELD_FORMAT, err.Error(), nil)
		return
	}
	defer r.Body.Close()

	// Hash password before saving
	hashPassword, _ := bcrypt.GenerateFromPassword([]byte(userInput.Password), bcrypt.DefaultCost)
	userInput.Password = string(hashPassword)

	if err := models.DB.Create(&userInput).Error; err != nil {
		helper.GenerateErrorResponse(w, helper.SERVER_GENERAL_ERROR, err.Error(), nil)
		return
	}

	helper.GenerateResponse(w, helper.OK, userInput)
}

// GetUser handles retrieving a user by ID
func GetUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		helper.GenerateErrorResponse(w, helper.INVALID_FIELD_FORMAT, "Invalid ID format", nil)
		return
	}

	var user models.User
	if err := models.DB.First(&user, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			helper.GenerateErrorResponse(w, helper.SERVER_GENERAL_ERROR, "User not found", nil)
			return
		}
		helper.GenerateErrorResponse(w, helper.SERVER_GENERAL_ERROR, err.Error(), nil)
		return
	}

	helper.GenerateResponse(w, helper.OK, user)
}

// UpdateUser handles updating an existing user
func UpdateUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		helper.GenerateErrorResponse(w, helper.INVALID_FIELD_FORMAT, "Invalid ID format", nil)
		return
	}

	var userInput models.User
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&userInput); err != nil {
		helper.GenerateErrorResponse(w, helper.INVALID_FIELD_FORMAT, err.Error(), nil)
		return
	}
	defer r.Body.Close()

	var user models.User
	if err := models.DB.First(&user, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			helper.GenerateErrorResponse(w, helper.SERVER_GENERAL_ERROR, "User not found", nil)
			return
		}
		helper.GenerateErrorResponse(w, helper.SERVER_GENERAL_ERROR, err.Error(), nil)
		return
	}

	user.NamaLengkap = userInput.NamaLengkap
	user.Username = userInput.Username
	if userInput.Password != "" {
		hashPassword, _ := bcrypt.GenerateFromPassword([]byte(userInput.Password), bcrypt.DefaultCost)
		user.Password = string(hashPassword)
	}

	if err := models.DB.Save(&user).Error; err != nil {
		helper.GenerateErrorResponse(w, helper.SERVER_GENERAL_ERROR, err.Error(), nil)
		return
	}

	helper.GenerateResponse(w, helper.OK, user)
}

// DeleteUser handles deleting a user by ID
func DeleteUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		helper.GenerateErrorResponse(w, helper.INVALID_FIELD_FORMAT, "Invalid ID format", nil)
		return
	}

	if err := models.DB.Delete(&models.User{}, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			helper.GenerateErrorResponse(w, helper.SERVER_GENERAL_ERROR, "User not found", nil)
			return
		}
		helper.GenerateErrorResponse(w, helper.SERVER_GENERAL_ERROR, err.Error(), nil)
		return
	}

	helper.GenerateResponse(w, helper.OK, nil)
}
