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
		},
		{
			"id":           2,
			"nama_product": "Celana",
			"stok":         10000,
		},
		{
			"id":           3,
			"nama_product": "Sepatu",
			"stok":         500,
		},
	}

	itemsPerPage := 2
	pagination := helper.Paginate(r, data, itemsPerPage)

	helper.ResponseJSON(w, http.StatusOK, "Data produk berhasil diambil", pagination)
}
