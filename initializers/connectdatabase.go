package initializers

import (
	"fmt"
	"log"

	//"log"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var DB *gorm.DB

func ConnectDatabase() {
	var err error
	fmt.Println("connecting to db")
	dsn := "host=localhost user=sai password= dbname=sai port=5432 sslmode=disable TimeZone=Asia/Kolkata"
	DB, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Println("failed to connect to database", err)
		panic("Failed to connect to db ")
	}

}
