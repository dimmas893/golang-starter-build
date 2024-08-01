package routes

import (
	"net/http"

	"github.com/gorilla/mux"
	"github.com/jeypc/go-jwt-mux/controllers/usercontroller"
	middleware "github.com/jeypc/go-jwt-mux/middlewares"
)

func SetupUserRouter(r *mux.Router) {
	// Rute user dengan prefiks "/api/users"
	userRouter := r.PathPrefix("/api/users").Subrouter()

	// Apply logging middleware to userRouter
	userRouter.Use(middleware.LoggingMiddleware)

	// Handle GET request for users
	userRouter.Handle("", http.HandlerFunc(usercontroller.GetUsers)).Methods("GET")
}
