package main

import (
	"log"
	"log/slog"
	"net/http"
	"os"

	"github.com/go-playground/validator/v10"
	"github.com/joho/godotenv"
)

// Declare a global logger variable
var logger *slog.Logger
var fiatRateService *FiatRateService
var fiatHandler *FiatHandler

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Error loading .env file")
	}

	// Initialize the global logger with JSON handler
	logger = slog.New(slog.NewJSONHandler(os.Stdout, nil))

	notificationService = NewNotificationService()
	webhookService = NewWebhookService()
	checkoutService = NewCheckoutService()
	walletService = &WalletService{}

	// Initialize the fiat rate service and handler
	fiatRateService = NewFiatRateService()
	fiatHandler = &FiatHandler{
		Validator: validator.New(),
		Service:   fiatRateService,
	}

	InitDB()
	r := InitRoutes()
	go walletListener.Start()

	port := os.Getenv("APP_PORT")
	if port == "" {
		port = "2121"
	}

	logger.Info("Starting server on port", slog.String("port", port)) // Use the global logger
	err = http.ListenAndServe(":"+port, r)
	if err != nil {
		logger.Error("Server failed", err.Error()) // Use the global logger
		log.Fatal(err)
	}
}
