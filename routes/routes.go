package routes

import (
	"github.com/gorilla/mux"
)

func SetupRouter() *mux.Router {
	r := mux.NewRouter()

	// Setup rute untuk otentikasi
	SetupAuthRouter(r)

	// Setup rute untuk produk
	SetupProductRouter(r)

	SetupUserRouter(r)

	return r
}
