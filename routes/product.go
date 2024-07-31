package routes

import (
	"net/http"

	"github.com/gorilla/mux"
	"github.com/jeypc/go-jwt-mux/controllers/productcontroller"
	middleware "github.com/jeypc/go-jwt-mux/middlewares"
)

func SetupProductRouter(r *mux.Router) {
	// Rute produk dengan prefiks "/api/products"
	productRouter := r.PathPrefix("/api/products").Subrouter()
	productRouter.Handle("", middleware.JWTMiddleware(http.HandlerFunc(productcontroller.Index))).Methods("GET")
}
