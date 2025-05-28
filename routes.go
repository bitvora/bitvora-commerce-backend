package main

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/cors"
)

func InitRoutes() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(60 * time.Second))

	// allow cors
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"http://localhost:3000"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token", "Session-ID"},
		AllowCredentials: true,
	}))

	// Add API Key middleware
	r.Use(APIKeyMiddleware)

	r.Get("/", HandleHome)
	r.Post("/register", userHandler.Register)
	r.Post("/login", userHandler.Login)
	r.Post("/logout", userHandler.Logout)
	r.Get("/l/{id}", paymentLinkHandler.PublicLinkHandler)
	r.Get("/c/{id}", checkoutHandler.PublicLinkHandler)
	r.Get("/c/{id}/poll", checkoutHandler.PollInvoice)

	r.Group(func(r chi.Router) {
		r.Use(CombinedAuthMiddleware)

		r.Get("/dashboard", userHandler.Dashboard)
		r.Post("/account", accountHandler.Create)
		r.Put("/account/{id}", accountHandler.Update)
		r.Get("/account", accountHandler.GetAll)
		r.Get("/account/{id}", accountHandler.Get)
		r.Delete("/account/{id}", accountHandler.Delete)

		r.Get("/dashboard/{accountID}/sales/daily/{date}", dashboardHandler.GetDailySales)
		r.Get("/dashboard/{accountID}/sales/7-days/{date}", dashboardHandler.GetLast7DaysSales)
		r.Get("/dashboard/{accountID}/sales/30-days/{date}", dashboardHandler.GetLast30DaysSales)
		r.Get("/dashboard/{accountID}/sales/6-months/{date}", dashboardHandler.GetLast6MonthsSales)
		r.Get("/dashboard/{accountID}/sales/12-months/{date}", dashboardHandler.GetLast12MonthsSales)

		// New customer metrics endpoints
		r.Get("/dashboard/{accountID}/customers/daily/{date}", dashboardHandler.GetDailyCustomers)
		r.Get("/dashboard/{accountID}/customers/7-days/{date}", dashboardHandler.GetLast7DaysNewCustomers)
		r.Get("/dashboard/{accountID}/customers/30-days/{date}", dashboardHandler.GetLast30DaysNewCustomers)
		r.Get("/dashboard/{accountID}/customers/6-months/{date}", dashboardHandler.GetLast6MonthsNewCustomers)
		r.Get("/dashboard/{accountID}/customers/12-months/{date}", dashboardHandler.GetLast12MonthsNewCustomers)

		r.Get("/dashboard/{accountID}/subscribers/daily/{date}", dashboardHandler.GetDailyActiveSubscribers)
		r.Get("/dashboard/{accountID}/subscribers/7-days/{date}", dashboardHandler.GetLast7DaysActiveSubscribers)
		r.Get("/dashboard/{accountID}/subscribers/30-days/{date}", dashboardHandler.GetLast30DaysActiveSubscribers)
		r.Get("/dashboard/{accountID}/subscribers/6-months/{date}", dashboardHandler.GetLast6MonthsActiveSubscribers)
		r.Get("/dashboard/{accountID}/subscribers/12-months/{date}", dashboardHandler.GetLast12MonthsActiveSubscribers)

		r.Route("/api-key", func(r chi.Router) {
			r.Post("/", apiKeyHandler.Create)
			r.Get("/", apiKeyHandler.GetAll)
			r.Get("/{id}", apiKeyHandler.Get)
			r.Put("/{id}", apiKeyHandler.Update)
			r.Delete("/{id}", apiKeyHandler.Delete)
			r.Post("/{id}/lock", apiKeyHandler.Lock)
			r.Get("/account/{accountId}", apiKeyHandler.GetByAccount)
		})

		r.Route("/webhook", func(r chi.Router) {
			r.Post("/", webhookHandler.Create)
			r.Get("/{id}", webhookHandler.Get)
			r.Put("/{id}", webhookHandler.Update)
			r.Delete("/{id}", webhookHandler.Delete)
			r.Post("/{id}/regenerate-secret", webhookHandler.RegenerateSecret)
			r.Get("/account/{accountId}", webhookHandler.GetByAccount)

			r.Get("/{id}/deliveries", webhookHandler.GetDeliveries)
			r.Post("/{id}/deliveries/{deliveryId}/retry", webhookHandler.RetryDelivery)
		})

		r.Post("/product", productHandler.Create)
		r.Put("/product/{id}", productHandler.Update)
		r.Get("/product", productHandler.GetAll)
		r.Get("/product/{id}", productHandler.Get)
		r.Get("/product/account/{accountId}", productHandler.GetByAccount)
		r.Delete("/product/{id}", productHandler.Delete)

		r.Post("/customer", customerHandler.Create)
		r.Put("/customer/{id}", customerHandler.Update)
		r.Get("/customer", customerHandler.GetAll)
		r.Get("/customer/{id}", customerHandler.Get)
		r.Get("/customer/account/{accountId}", customerHandler.GetByAccount)
		r.Delete("/customer/{id}", customerHandler.Delete)

		r.Post("/subscription", subscriptionHandler.Create)
		r.Put("/subscription/{id}", subscriptionHandler.Update)
		r.Get("/subscription", subscriptionHandler.GetAll)
		r.Get("/subscription/{id}", subscriptionHandler.Get)
		r.Get("/subscription/account/{accountId}", subscriptionHandler.GetByAccount)
		r.Get("/subscription/customer/{customerId}", subscriptionHandler.GetByCustomer)
		r.Get("/subscription/product/{productId}", subscriptionHandler.GetByProduct)
		r.Delete("/subscription/{id}", subscriptionHandler.Delete)

		r.Post("/wallet", walletHandler.Create)
		r.Get("/wallet", walletHandler.GetAll)
		r.Get("/wallet/{id}", walletHandler.Get)
		r.Get("/wallet/account/{accountId}", walletHandler.GetByAccount)
		r.Delete("/wallet/{id}", walletHandler.Delete)

		r.Get("/wallet/balance", walletHandler.GetBalance)
		r.Get("/wallet/transactions", walletHandler.GetTransactions)
		r.Post("/wallet/withdraw", walletHandler.Withdraw)
		r.Post("/invoice", walletHandler.MakeInvoice)
		r.Post("/checkout", checkoutHandler.Create)
		r.Get("/checkout/{id}", checkoutHandler.Get)
		r.Post("/checkout/{id}/subscribe", checkoutHandler.ConnectWallet)
		r.Get("/checkout/account/{accountId}", checkoutHandler.GetAllByAccount)

		r.Route("/payment-link", func(r chi.Router) {
			r.Get("/", paymentLinkHandler.List)
			r.Post("/", paymentLinkHandler.Create)
			r.Get("/{id}", paymentLinkHandler.Get)
			r.Put("/{id}", paymentLinkHandler.Update)
			r.Delete("/{id}", paymentLinkHandler.Delete)
			r.Get("/account/{accountID}", paymentLinkHandler.ListByAccount)
		})

		r.Route("/notification-settings", func(r chi.Router) {
			r.Get("/account/{accountId}", notificationHandler.GetSettings)
			r.Post("/", notificationHandler.UpdateSettings)
		})

		r.Route("/fiat", func(r chi.Router) {
			r.Get("/rates", fiatHandler.GetRates)
			r.Get("/convert/to-fiat/{currency}", fiatHandler.ConvertSatoshisToFiat)
			r.Get("/convert/to-sats/{currency}", fiatHandler.ConvertFiatToSatoshis)
		})

		r.Get("/dashboard/{accountID}/mrr/7-days/{date}", dashboardHandler.GetLast7DaysMRR)
		r.Get("/dashboard/{accountID}/mrr/30-days/{date}", dashboardHandler.GetLast30DaysMRR)
		r.Get("/dashboard/{accountID}/mrr/6-months/{date}", dashboardHandler.GetLast6MonthsMRR)
		r.Get("/dashboard/{accountID}/mrr/12-months/{date}", dashboardHandler.GetLast12MonthsMRR)
		r.Get("/dashboard/{accountID}/mrr/daily/{date}", dashboardHandler.GetDailyMRR)
	})

	return r
}
