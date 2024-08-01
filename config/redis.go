package config

import (
	"context"
	"os"

	"log"

	"github.com/go-redis/redis/v8"
	"github.com/joho/godotenv"
)

var RedisClient *redis.Client
var Ctx = context.Background()

func InitRedis() {
	// Load environment variables from .env file
	if err := godotenv.Load(); err != nil {
		log.Fatalf("Error loading .env file: %v", err)
	}

	redisHost := os.Getenv("REDIS_HOST")
	redisPort := os.Getenv("REDIS_PORT")

	RedisClient = redis.NewClient(&redis.Options{
		Addr: redisHost + ":" + redisPort, // Use environment variables
	})
}
