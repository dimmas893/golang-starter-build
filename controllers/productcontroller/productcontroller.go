package productcontroller

import (
	"net/http"
	"strconv"

	"github.com/jeypc/go-jwt-mux/helper"
)

func Index(w http.ResponseWriter, r *http.Request) {
	data := []map[string]interface{}{
		{
			"id":           1,
			"nama_product": "Kemeja",
			"stok":         1000,
			"harga":        helper.FormatRupiah(150000),
		},
		{
			"id":           2,
			"nama_product": "Celana",
			"stok":         10000,
			"harga":        helper.FormatRupiah(200000),
		},
		{
			"id":           3,
			"nama_product": "Sepatu",
			"stok":         500,
			"harga":        helper.FormatRupiah(350000),
		},
		{
			"id":           4,
			"nama_product": "Sepatu",
			"stok":         500,
			"harga":        helper.FormatRupiah(350000),
		},
		{
			"id":           5,
			"nama_product": "Sepatu",
			"stok":         500,
			"harga":        helper.FormatRupiah(350000),
		},
		{
			"id":           6,
			"nama_product": "Sepatu",
			"stok":         500,
			"harga":        helper.FormatRupiah(350000),
		},
		{
			"id":           7,
			"nama_product": "Sepatu",
			"stok":         500,
			"harga":        helper.FormatRupiah(350000),
		},
		{
			"id":           8,
			"nama_product": "Sepatu",
			"stok":         500,
			"harga":        helper.FormatRupiah(350000),
		},
	}

	// Read pagination parameters from the request
	perPageStr := r.URL.Query().Get("per_page")
	pageStr := r.URL.Query().Get("page")

	perPage, err := strconv.Atoi(perPageStr)
	if err != nil || perPage <= 0 {
		perPage = 5 // Default items per page
	}

	page, err := strconv.Atoi(pageStr)
	if err != nil || page <= 0 {
		page = 1 // Default page number
	}

	// Paginate the data
	pagination := helper.CreatePagination(r, data, perPage, int64(len(data)))

	// Slice the data for the current page
	startIndex := (page - 1) * perPage
	endIndex := startIndex + perPage
	if endIndex > len(data) {
		endIndex = len(data)
	}
	pagination.Items = data[startIndex:endIndex]

	helper.ResponsePaginatedJSON(w, helper.OK, "Data produk berhasil diambil", pagination)
	// helper.PaginateResponse(w, helper.OK, *pagination)
}
