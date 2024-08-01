package usercontroller

import (
	"net/http"
	"strconv"

	"github.com/jeypc/go-jwt-mux/helper"
	"github.com/jeypc/go-jwt-mux/models"
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
		perPage, _    = strconv.Atoi(r.URL.Query().Get("per_page"))
		page, _       = strconv.Atoi(r.URL.Query().Get("page"))
	)

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

	query := models.DB.Model(&models.User{})

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

	// Apply pagination
	query = query.Order(sortBy + " " + sortDirection).
		Limit(perPage).
		Offset((page - 1) * perPage).
		Find(&users)

	if query.Error != nil {
		helper.GenerateErrorResponse(w, helper.SERVER_GENERAL_ERROR, "Database error", query.Error.Error())
		return
	}

	// Convert users to []map[string]interface{} for pagination
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

	helper.ResponsePaginatedJSON(w, helper.OK, "Data users berhasil diambil", pagination)
}
