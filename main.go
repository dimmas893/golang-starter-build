package main

import (
	"log"
	"net/http"

	"github.com/jeypc/go-jwt-mux/models"
	"github.com/jeypc/go-jwt-mux/routes"
)

func main() {
	models.ConnectDatabase()
	r := routes.SetupRouter()
	log.Fatal(http.ListenAndServe(":8081", r))
}
