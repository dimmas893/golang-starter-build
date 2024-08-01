package routes

import (
	"github.com/gorilla/mux"
)

// SetupRouter mengatur semua rute
func SetupRouter() *mux.Router {
	r := mux.NewRouter()

	// Setup rute untuk otentikasi
	SetupAuthRouter(r)

	// Setup rute untuk produk
	SetupProductRouter(r)

	// Setup rute untuk pengguna
	SetupUserRouter(r)

	SetupSecurityRoutes(r)

	return r
}
