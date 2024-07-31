package productcontroller

import (
	"net/http"

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

	itemsPerPage := 5
	pagination := helper.Paginate(r, data, itemsPerPage)

	helper.ResponsePaginatedJSON(w, http.StatusOK, "Data produk berhasil diambil", pagination)
}
