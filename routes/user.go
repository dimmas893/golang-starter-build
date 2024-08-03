package routes

import (
	"github.com/gorilla/mux"
	"github.com/jeypc/go-jwt-mux/controllers/usercontroller"
	middleware "github.com/jeypc/go-jwt-mux/middlewares"
)

func SetupUserRouter(r *mux.Router) {
	// Rute user dengan prefiks "/api/users"
	userRouter := r.PathPrefix("/api/users").Subrouter()

	// Apply logging middleware to userRouter
	userRouter.Use(middleware.LoggingMiddleware)

	userRouter.HandleFunc("", usercontroller.GetUsers).Methods("GET")
	userRouter.HandleFunc("", usercontroller.CreateUser).Methods("POST")
	userRouter.HandleFunc("/{id}", usercontroller.GetUser).Methods("GET")
	userRouter.HandleFunc("/{id}", usercontroller.UpdateUser).Methods("PUT")
	userRouter.HandleFunc("/{id}", usercontroller.DeleteUser).Methods("DELETE")
	userRouter.HandleFunc("", usercontroller.GetUsers).Methods("GET")
}
