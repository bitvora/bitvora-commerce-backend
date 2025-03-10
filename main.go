package main

import (
	"log"
	"net/http"
	"os"

	"github.com/joho/godotenv"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Error loading .env file")
	}

	notificationService = NewNotificationService()
	webhookService = NewWebhookService()
	checkoutService = NewCheckoutService()

	InitDB()
	r := InitRoutes()
	go walletListener.Start()

	port := os.Getenv("APP_PORT")
	if port == "" {
		port = "2121"
	}

	log.Printf("Starting server on port %s", port)
	err = http.ListenAndServe(":"+port, r)
	if err != nil {
		log.Fatal(err)
	}
}
