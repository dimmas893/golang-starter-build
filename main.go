package main

import (
	"log"
	"net/http"

	"github.com/jeypc/go-jwt-mux/config"
	"github.com/jeypc/go-jwt-mux/models"
	"github.com/jeypc/go-jwt-mux/routes"
)

func main() {
	config.InitRedis() // Inisialisasi Redis
	models.ConnectDatabase()
	r := routes.SetupRouter()
	log.Fatal(http.ListenAndServe(":8081", r))
}
