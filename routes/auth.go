package routes

import (
	"github.com/gorilla/mux"
	"github.com/jeypc/go-jwt-mux/controllers/authcontroller"
)

func SetupAuthRouter(r *mux.Router) {
	// Rute untuk login, register, dan logout
	r.HandleFunc("/login", authcontroller.Login).Methods("POST")
	r.HandleFunc("/logout", authcontroller.Logout).Methods("GET")
	r.HandleFunc("/profile", authcontroller.GetProfile).Methods("GET")
}
