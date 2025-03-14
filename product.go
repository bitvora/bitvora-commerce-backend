package main

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
)

type Product struct {
	ID                 uuid.UUID  `db:"id" json:"id"`
	UserID             uuid.UUID  `db:"user_id" json:"user_id"`
	AccountID          uuid.UUID  `db:"account_id" json:"account_id"`
	Name               string     `db:"name" json:"name"`
	Description        *string    `db:"description" json:"description,omitempty"`
	Image              *string    `db:"image" json:"image,omitempty"`
	IsRecurring        bool       `db:"is_recurring" json:"is_recurring"`
	Amount             float64    `db:"amount" json:"amount"`     // Price amount
	Currency           string     `db:"currency" json:"currency"` // Currency code
	BillingPeriodHours *int       `db:"billing_period_hours" json:"billing_period_hours,omitempty"`
	CreatedAt          time.Time  `db:"created_at" json:"created_at"`
	UpdatedAt          time.Time  `db:"updated_at" json:"updated_at"`
	DeletedAt          *time.Time `db:"deleted_at" json:"deleted_at,omitempty"`
}

type ProductRepository struct{}
type ProductService struct{}

var productRepository = &ProductRepository{}
var productService = &ProductService{}

func (r *ProductRepository) Create(product *Product) (*Product, error) {
	err := db.Get(product, `
		INSERT INTO products (
			id, user_id, account_id, name, description, image, 
			is_recurring, amount, currency, billing_period_hours,
			created_at, updated_at, deleted_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, 
			$7, $8, $9, $10,
			$11, $12, $13
		) RETURNING *`,
		product.ID, product.UserID, product.AccountID, product.Name, product.Description, product.Image,
		product.IsRecurring, product.Amount, product.Currency, product.BillingPeriodHours,
		product.CreatedAt, product.UpdatedAt, product.DeletedAt)
	return product, err
}

func (r *ProductRepository) Update(product *Product) error {
	_, err := db.Exec(`
		UPDATE products SET 
			name=$1, description=$2, image=$3, 
			is_recurring=$4, amount=$5, currency=$6, billing_period_hours=$7,
			updated_at=$8, deleted_at=$9 
		WHERE id=$10`,
		product.Name, product.Description, product.Image,
		product.IsRecurring, product.Amount, product.Currency, product.BillingPeriodHours,
		product.UpdatedAt, product.DeletedAt, product.ID)
	return err
}

func (r *ProductRepository) Get(id uuid.UUID) (*Product, error) {
	product := &Product{}
	err := db.Get(product, "SELECT * FROM products WHERE id=$1 AND deleted_at IS NULL", id)
	return product, err
}

func (r *ProductRepository) GetByUser(userID uuid.UUID) ([]*Product, error) {
	products := []*Product{}
	err := db.Select(&products, "SELECT * FROM products WHERE user_id=$1 AND deleted_at IS NULL ORDER BY created_at DESC", userID)
	return products, err
}

func (r *ProductRepository) GetByAccount(accountID uuid.UUID) ([]*Product, error) {
	products := []*Product{}
	err := db.Select(&products, "SELECT * FROM products WHERE account_id=$1 AND deleted_at IS NULL ORDER BY created_at DESC", accountID)
	return products, err
}

func (r *ProductRepository) Delete(id uuid.UUID) error {
	_, err := db.Exec("UPDATE products SET deleted_at=$1 WHERE id=$2", time.Now(), id)
	return err
}

func (s *ProductService) Create(product *Product) (*Product, error) {
	product.CreatedAt = time.Now()
	product.UpdatedAt = time.Now()
	return productRepository.Create(product)
}

func (s *ProductService) Update(product *Product) error {
	product.UpdatedAt = time.Now()
	return productRepository.Update(product)
}

func (s *ProductService) Get(id uuid.UUID) (*Product, error) {
	return productRepository.Get(id)
}

func (s *ProductService) GetByUser(userID uuid.UUID) ([]*Product, error) {
	return productRepository.GetByUser(userID)
}

func (s *ProductService) GetByAccount(accountID uuid.UUID) ([]*Product, error) {
	return productRepository.GetByAccount(accountID)
}

func (s *ProductService) Delete(id uuid.UUID) error {
	return productRepository.Delete(id)
}

type ProductHandler struct {
	Validator *validator.Validate
}

var productHandler = &ProductHandler{
	Validator: validator.New(),
}

func (h *ProductHandler) Create(w http.ResponseWriter, r *http.Request) {
	var input struct {
		AccountID          uuid.UUID `json:"account_id" validate:"required"`
		Name               string    `json:"name" validate:"required"`
		Description        *string   `json:"description,omitempty"`
		Image              *string   `json:"image,omitempty"`
		IsRecurring        bool      `json:"is_recurring"`
		Amount             float64   `json:"amount" validate:"required,gt=0"`
		Currency           string    `json:"currency" validate:"required"`
		BillingPeriodHours *int      `json:"billing_period_hours,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		JsonResponse(w, http.StatusBadRequest, "Invalid request", err.Error())
		return
	}

	if err := h.Validator.Struct(input); err != nil {
		JsonResponse(w, http.StatusBadRequest, "Invalid request", err.Error())
		return
	}

	// Validate currency (only 3-letter codes for fiat, or "btc"/"sats" for bitcoin)
	if input.Currency != "btc" && input.Currency != "sats" && len(input.Currency) != 3 {
		JsonResponse(w, http.StatusBadRequest, "Currency must be a 3-letter code or 'btc'/'sats'", nil)
		return
	}

	if input.IsRecurring && (input.BillingPeriodHours == nil || *input.BillingPeriodHours <= 0) {
		JsonResponse(w, http.StatusBadRequest, "Billing period hours required for recurring products", nil)
		return
	}

	user, err := GetUserFromContext(r.Context())
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error retrieving user", err.Error())
		return
	}

	account, err := accountService.Get(input.AccountID)
	if err != nil {
		JsonResponse(w, http.StatusBadRequest, "Invalid account ID", err.Error())
		return
	}

	if account.UserID != user.ID {
		JsonResponse(w, http.StatusForbidden, "You are not authorized to create products for this account", nil)
		return
	}

	// Normalize amounts for bitcoin currencies
	amount := input.Amount
	if input.Currency == "btc" {
		// Convert to a more precise decimal representation for BTC
		amount = input.Amount // Keep as is, will be interpreted as BTC
	}

	product := &Product{
		ID:                 uuid.New(),
		UserID:             user.ID,
		AccountID:          input.AccountID,
		Name:               input.Name,
		Description:        input.Description,
		Image:              input.Image,
		IsRecurring:        input.IsRecurring,
		Amount:             amount,
		Currency:           input.Currency,
		BillingPeriodHours: input.BillingPeriodHours,
	}

	createdProduct, err := productService.Create(product)
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error creating product", err.Error())
		return
	}

	JsonResponse(w, http.StatusCreated, "Product created successfully", createdProduct)
}

func (h *ProductHandler) Update(w http.ResponseWriter, r *http.Request) {
	productIDStr := chi.URLParam(r, "id")
	if productIDStr == "" {
		JsonResponse(w, http.StatusBadRequest, "Product ID is required", nil)
		return
	}

	productID, err := uuid.Parse(productIDStr)
	if err != nil {
		JsonResponse(w, http.StatusBadRequest, "Invalid product ID", err.Error())
		return
	}

	user, err := GetUserFromContext(r.Context())
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error retrieving user", err.Error())
		return
	}

	existingProduct, err := productService.Get(productID)
	if err != nil {
		JsonResponse(w, http.StatusNotFound, "Product not found", err.Error())
		return
	}

	if existingProduct.UserID != user.ID {
		JsonResponse(w, http.StatusForbidden, "You are not authorized to update this product", nil)
		return
	}

	var input struct {
		Name               string  `json:"name" validate:"required"`
		Description        *string `json:"description,omitempty"`
		Image              *string `json:"image,omitempty"`
		IsRecurring        bool    `json:"is_recurring"`
		Amount             float64 `json:"amount" validate:"required,gt=0"`
		Currency           string  `json:"currency" validate:"required"`
		BillingPeriodHours *int    `json:"billing_period_hours,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		JsonResponse(w, http.StatusBadRequest, "Invalid request", err.Error())
		return
	}

	if err := h.Validator.Struct(input); err != nil {
		JsonResponse(w, http.StatusBadRequest, "Invalid request", err.Error())
		return
	}

	// Validate currency (only 3-letter codes for fiat, or "btc"/"sats" for bitcoin)
	if input.Currency != "btc" && input.Currency != "sats" && len(input.Currency) != 3 {
		JsonResponse(w, http.StatusBadRequest, "Currency must be a 3-letter code or 'btc'/'sats'", nil)
		return
	}

	if input.IsRecurring && (input.BillingPeriodHours == nil || *input.BillingPeriodHours <= 0) {
		JsonResponse(w, http.StatusBadRequest, "Billing period hours required for recurring products", nil)
		return
	}

	// Normalize amounts for bitcoin currencies
	amount := input.Amount
	if input.Currency == "btc" {
		// Convert to a more precise decimal representation for BTC
		amount = input.Amount // Keep as is, will be interpreted as BTC
	}

	product := &Product{
		ID:                 existingProduct.ID,
		UserID:             existingProduct.UserID,
		AccountID:          existingProduct.AccountID,
		Name:               input.Name,
		Description:        input.Description,
		Image:              input.Image,
		IsRecurring:        input.IsRecurring,
		Amount:             amount,
		Currency:           input.Currency,
		BillingPeriodHours: input.BillingPeriodHours,
	}

	err = productService.Update(product)
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error updating product", err.Error())
		return
	}

	JsonResponse(w, http.StatusOK, "Product updated successfully", product)
}

func (h *ProductHandler) Get(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		JsonResponse(w, http.StatusBadRequest, "Invalid product ID", nil)
		return
	}

	product, err := productService.Get(id)
	if err != nil {
		JsonResponse(w, http.StatusNotFound, "Product not found", err.Error())
		return
	}

	user, err := GetUserFromContext(r.Context())
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error retrieving user", err.Error())
		return
	}

	if product.UserID != user.ID {
		JsonResponse(w, http.StatusForbidden, "You are not authorized to view this product", nil)
		return
	}

	JsonResponse(w, http.StatusOK, "Product retrieved successfully", product)
}

func (h *ProductHandler) GetAll(w http.ResponseWriter, r *http.Request) {
	user, err := GetUserFromContext(r.Context())
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error retrieving user", err.Error())
		return
	}

	products, err := productService.GetByUser(user.ID)
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error retrieving products", err.Error())
		return
	}

	JsonResponse(w, http.StatusOK, "Products retrieved successfully", products)
}

func (h *ProductHandler) GetByAccount(w http.ResponseWriter, r *http.Request) {
	accountIDStr := chi.URLParam(r, "accountId")
	accountID, err := uuid.Parse(accountIDStr)
	if err != nil {
		JsonResponse(w, http.StatusBadRequest, "Invalid account ID", nil)
		return
	}

	user, err := GetUserFromContext(r.Context())
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error retrieving user", err.Error())
		return
	}

	account, err := accountService.Get(accountID)
	if err != nil {
		JsonResponse(w, http.StatusNotFound, "Account not found", err.Error())
		return
	}

	if account.UserID != user.ID {
		JsonResponse(w, http.StatusForbidden, "You are not authorized to view products for this account", nil)
		return
	}

	products, err := productService.GetByAccount(accountID)
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error retrieving products", err.Error())
		return
	}

	JsonResponse(w, http.StatusOK, "Products retrieved successfully", products)
}

func (h *ProductHandler) Delete(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		JsonResponse(w, http.StatusBadRequest, "Invalid product ID", nil)
		return
	}

	product, err := productService.Get(id)
	if err != nil {
		JsonResponse(w, http.StatusNotFound, "Product not found", err.Error())
		return
	}

	user, err := GetUserFromContext(r.Context())
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error retrieving user", err.Error())
		return
	}

	if product.UserID != user.ID {
		JsonResponse(w, http.StatusForbidden, "You are not authorized to delete this product", nil)
		return
	}

	err = productService.Delete(id)
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error deleting product", err.Error())
		return
	}

	JsonResponse(w, http.StatusOK, "Product deleted successfully", nil)
}
