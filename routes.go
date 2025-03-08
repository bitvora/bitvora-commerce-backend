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

	r.Get("/", HandleHome)
	r.Post("/register", userHandler.Register)
	r.Post("/login", userHandler.Login)
	r.Post("/logout", userHandler.Logout)
	r.Get("/l/{id}", paymentLinkHandler.PublicLinkHandler)
	r.Get("/c/{id}", checkoutHandler.PublicLinkHandler)

	r.Group(func(r chi.Router) {
		r.Use(AuthMiddleware)

		r.Get("/dashboard", userHandler.Dashboard)
		r.Post("/account", accountHandler.Create)
		r.Put("/account/{id}", accountHandler.Update)
		r.Get("/account", accountHandler.GetAll)
		r.Get("/account/{id}", accountHandler.Get)
		r.Delete("/account/{id}", accountHandler.Delete)

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

		r.Post("/invoice", walletHandler.MakeInvoice)
		r.Post("/checkout", checkoutHandler.Create)
		r.Get("/checkout/{id}", checkoutHandler.Get)
		r.Get("/checkout/account/{accountId}", checkoutHandler.GetAllByAccount)

		// Payment links routes (protected)
		r.Route("/payment-link", func(r chi.Router) {
			r.Get("/", paymentLinkHandler.List)
			r.Post("/", paymentLinkHandler.Create)
			r.Get("/{id}", paymentLinkHandler.Get)
			r.Put("/{id}", paymentLinkHandler.Update)
			r.Delete("/{id}", paymentLinkHandler.Delete)
			r.Get("/account/{accountID}", paymentLinkHandler.ListByAccount)
		})
	})

	return r
}
