package main

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/chi/v5"
)

func InitRoutes() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(60 * time.Second))

	r.Get("/", HandleHome)
	r.Post("/register", userHandler.Register)
	r.Post("/login", userHandler.Login)
	r.Post("/logout", userHandler.Logout)

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
	})

	return r
}
