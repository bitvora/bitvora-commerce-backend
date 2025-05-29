package main

import (
	"log"
	"os"

	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
)

var db *sqlx.DB

func InitDB() {
	var err error

	dbUser := os.Getenv("POSTGRES_USER")
	dbPassword := os.Getenv("POSTGRES_PASSWORD")
	dbName := os.Getenv("POSTGRES_DB")
	dbPort := os.Getenv("POSTGRES_PORT")
	dbHost := os.Getenv("POSTGRES_HOST")

	connStr := "host=" + dbHost + " port=" + dbPort + " user=" + dbUser + " password=" + dbPassword + " dbname=" + dbName + " sslmode=disable"

	db, err = sqlx.Connect("postgres", connStr)
	if err != nil {
		log.Fatalln(err)
	}

	log.Println("Database connection established")
}

func GetDB() *sqlx.DB {
	return db
}
