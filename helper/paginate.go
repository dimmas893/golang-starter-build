package helper

import (
	"math"
	"net/http"
	"strconv"
)

type Pagination struct {
	Items       interface{} `json:"items"`
	CurrentPage int         `json:"current_page"`
	LastPage    int         `json:"last_page"`
	PerPage     int         `json:"per_page"`
	Total       int         `json:"total"`
}

func Paginate(r *http.Request, data []map[string]interface{}, itemsPerPage int) *Pagination {
	pageStr := r.URL.Query().Get("page")
	if pageStr == "" {
		pageStr = "1"
	}
	page, err := strconv.Atoi(pageStr)
	if err != nil || page < 1 {
		page = 1
	}

	totalItems := len(data)
	totalPages := int(math.Ceil(float64(totalItems) / float64(itemsPerPage)))

	startIndex := (page - 1) * itemsPerPage
	endIndex := startIndex + itemsPerPage
	if endIndex > totalItems {
		endIndex = totalItems
	}

	paginatedData := data[startIndex:endIndex]

	pagination := &Pagination{
		Items:       paginatedData,
		Total:       totalItems,
		CurrentPage: page,
		LastPage:    totalPages,
		PerPage:     itemsPerPage,
	}

	return pagination
}
