package models

import (
	"fmt"
	"log"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

var DB *gorm.DB

func ConnectDatabase() {
	dsn := "root:Anandadimmas,123@tcp(localhost:3306)/go_jwt_mux"
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal("Gagal koneksi database: ", err)
	}

	db.AutoMigrate(&User{})

	DB = db
	fmt.Println("Database connection established")
}
