package routes

import (
	"net/http"

	"github.com/gorilla/mux"
	"github.com/jeypc/go-jwt-mux/controllers/usercontroller"
)

func SetupUserRouter(r *mux.Router) {
	// Rute user dengan prefiks "/api/users"
	userRouter := r.PathPrefix("/api/users").Subrouter()
	userRouter.Handle("", http.HandlerFunc(usercontroller.GetUsers)).Methods("GET")
}
