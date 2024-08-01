package helper

import (
	"encoding/json"
	"math"
	"net/http"
	"strconv"
)

type Pagination struct {
	Items       interface{} `json:"items"`
	CurrentPage int         `json:"current_page"`
	LastPage    int         `json:"last_page"`
	PerPage     int         `json:"per_page"`
	Total       int64       `json:"total"`
}

type PaginatedResponse struct {
	ResponseCode    string      `json:"response_code"`
	ResponseMessage string      `json:"response_message"`
	Items           interface{} `json:"items"`
	CurrentPage     int         `json:"current_page"`
	LastPage        int         `json:"last_page"`
	PerPage         int         `json:"per_page"`
	Total           int64       `json:"total"`
}

func CreatePagination(r *http.Request, data []map[string]interface{}, itemsPerPage int, totalItems int64) *Pagination {
	pageStr := r.URL.Query().Get("page")
	if pageStr == "" {
		pageStr = "1"
	}
	page, err := strconv.Atoi(pageStr)
	if err != nil || page < 1 {
		page = 1
	}

	totalPages := int(math.Ceil(float64(totalItems) / float64(itemsPerPage)))

	return &Pagination{
		Items:       data,
		Total:       totalItems,
		CurrentPage: page,
		LastPage:    totalPages,
		PerPage:     itemsPerPage,
	}
}

func ResponsePaginatedJSON(w http.ResponseWriter, code ResponseCode, message string, pagination *Pagination) {
	response := PaginatedResponse{
		ResponseCode:    string(code),
		ResponseMessage: code.Message(),
		Items:           pagination.Items,
		CurrentPage:     pagination.CurrentPage,
		LastPage:        pagination.LastPage,
		PerPage:         pagination.PerPage,
		Total:           pagination.Total,
	}

	jsonResponse, _ := json.Marshal(response)
	w.Header().Add("Content-Type", "application/json")
	statusCode, _ := strconv.Atoi(string(code)[:3])
	w.WriteHeader(statusCode)
	w.Write(jsonResponse)
}
