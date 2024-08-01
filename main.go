package main

import (
	"log"
	"net/http"
	"os"

	"github.com/jeypc/go-jwt-mux/config"
	"github.com/jeypc/go-jwt-mux/models"
	"github.com/jeypc/go-jwt-mux/routes"
	"github.com/joho/godotenv"
)

func main() {
	// Load environment variables from .env file
	if err := godotenv.Load(); err != nil {
		log.Fatalf("Error loading .env file: %v", err)
	}

	config.InitRedis() // Initialize Redis
	models.ConnectDatabase()

	// Set up router
	r := routes.SetupRouter()

	// Get port from environment variable, default to 8081 if not set
	port := os.Getenv("PORT")
	if port == "" {
		port = "8081"
	}

	log.Fatal(http.ListenAndServe(":"+port, r))
}
