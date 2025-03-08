package main

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
)

type Customer struct {
	ID                   uuid.UUID  `db:"id" json:"id"`
	UserID               uuid.UUID  `db:"user_id" json:"user_id"`
	AccountID            uuid.UUID  `db:"account_id" json:"account_id"`
	Name                 *string    `db:"name" json:"name,omitempty"`
	Email                *string    `db:"email" json:"email,omitempty"`
	Description          *string    `db:"description" json:"description,omitempty"`
	BillingAddressLine1  *string    `db:"billing_address_line1" json:"billing_address_line1,omitempty"`
	BillingAddressLine2  *string    `db:"billing_address_line2" json:"billing_address_line2,omitempty"`
	BillingCity          *string    `db:"billing_city" json:"billing_city,omitempty"`
	BillingState         *string    `db:"billing_state" json:"billing_state,omitempty"`
	BillingPostalCode    *string    `db:"billing_postal_code" json:"billing_postal_code,omitempty"`
	BillingCountry       *string    `db:"billing_country" json:"billing_country,omitempty"`
	ShippingAddressLine1 *string    `db:"shipping_address_line1" json:"shipping_address_line1,omitempty"`
	ShippingAddressLine2 *string    `db:"shipping_address_line2" json:"shipping_address_line2,omitempty"`
	ShippingCity         *string    `db:"shipping_city" json:"shipping_city,omitempty"`
	ShippingState        *string    `db:"shipping_state" json:"shipping_state,omitempty"`
	ShippingPostalCode   *string    `db:"shipping_postal_code" json:"shipping_postal_code,omitempty"`
	ShippingCountry      *string    `db:"shipping_country" json:"shipping_country,omitempty"`
	PhoneNumber          *string    `db:"phone_number" json:"phone_number,omitempty"`
	Currency             *string    `db:"currency" json:"currency,omitempty"`
	CreatedAt            time.Time  `db:"created_at" json:"created_at"`
	UpdatedAt            time.Time  `db:"updated_at" json:"updated_at"`
	DeletedAt            *time.Time `db:"deleted_at" json:"deleted_at,omitempty"`
}

type CustomerRepository struct{}
type CustomerService struct{}

var customerRepository = &CustomerRepository{}
var customerService = &CustomerService{}

func (r *CustomerRepository) Create(customer *Customer) (*Customer, error) {
	err := db.Get(customer, `
		INSERT INTO customers (
			id, user_id, account_id, name, email, description, 
			billing_address_line1, billing_address_line2, billing_city, billing_state, billing_postal_code, billing_country,
			shipping_address_line1, shipping_address_line2, shipping_city, shipping_state, shipping_postal_code, shipping_country,
			phone_number, currency, created_at, updated_at, deleted_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, 
			$7, $8, $9, $10, $11, $12,
			$13, $14, $15, $16, $17, $18,
			$19, $20, $21, $22, $23
		) RETURNING *`,
		customer.ID, customer.UserID, customer.AccountID, customer.Name, customer.Email, customer.Description,
		customer.BillingAddressLine1, customer.BillingAddressLine2, customer.BillingCity, customer.BillingState, customer.BillingPostalCode, customer.BillingCountry,
		customer.ShippingAddressLine1, customer.ShippingAddressLine2, customer.ShippingCity, customer.ShippingState, customer.ShippingPostalCode, customer.ShippingCountry,
		customer.PhoneNumber, customer.Currency, customer.CreatedAt, customer.UpdatedAt, customer.DeletedAt)
	return customer, err
}

func (r *CustomerRepository) Update(customer *Customer) error {
	_, err := db.Exec(`
		UPDATE customers SET 
			name=$1, email=$2, description=$3, 
			billing_address_line1=$4, billing_address_line2=$5, billing_city=$6, billing_state=$7, billing_postal_code=$8, billing_country=$9,
			shipping_address_line1=$10, shipping_address_line2=$11, shipping_city=$12, shipping_state=$13, shipping_postal_code=$14, shipping_country=$15,
			phone_number=$16, currency=$17, updated_at=$18, deleted_at=$19
		WHERE id=$20`,
		customer.Name, customer.Email, customer.Description,
		customer.BillingAddressLine1, customer.BillingAddressLine2, customer.BillingCity, customer.BillingState, customer.BillingPostalCode, customer.BillingCountry,
		customer.ShippingAddressLine1, customer.ShippingAddressLine2, customer.ShippingCity, customer.ShippingState, customer.ShippingPostalCode, customer.ShippingCountry,
		customer.PhoneNumber, customer.Currency, customer.UpdatedAt, customer.DeletedAt, customer.ID)
	return err
}

func (r *CustomerRepository) Get(id uuid.UUID) (*Customer, error) {
	customer := &Customer{}
	err := db.Get(customer, "SELECT * FROM customers WHERE id=$1 AND deleted_at IS NULL", id)
	return customer, err
}

func (r *CustomerRepository) GetByUser(userID uuid.UUID) ([]*Customer, error) {
	customers := []*Customer{}
	err := db.Select(&customers, "SELECT * FROM customers WHERE user_id=$1 AND deleted_at IS NULL ORDER BY created_at DESC", userID)
	return customers, err
}

func (r *CustomerRepository) GetByAccount(accountID uuid.UUID) ([]*Customer, error) {
	customers := []*Customer{}
	err := db.Select(&customers, "SELECT * FROM customers WHERE account_id=$1 AND deleted_at IS NULL ORDER BY created_at DESC", accountID)
	return customers, err
}

func (r *CustomerRepository) Delete(id uuid.UUID) error {
	_, err := db.Exec("UPDATE customers SET deleted_at=$1 WHERE id=$2", time.Now(), id)
	return err
}

func (s *CustomerService) Create(customer *Customer) (*Customer, error) {
	customer.CreatedAt = time.Now()
	customer.UpdatedAt = time.Now()
	return customerRepository.Create(customer)
}

func (s *CustomerService) Update(customer *Customer) error {
	customer.UpdatedAt = time.Now()
	return customerRepository.Update(customer)
}

func (s *CustomerService) Get(id uuid.UUID) (*Customer, error) {
	return customerRepository.Get(id)
}

func (s *CustomerService) GetByUser(userID uuid.UUID) ([]*Customer, error) {
	return customerRepository.GetByUser(userID)
}

func (s *CustomerService) GetByAccount(accountID uuid.UUID) ([]*Customer, error) {
	return customerRepository.GetByAccount(accountID)
}

func (s *CustomerService) Delete(id uuid.UUID) error {
	return customerRepository.Delete(id)
}

type CustomerHandler struct {
	Validator *validator.Validate
}

var customerHandler = &CustomerHandler{
	Validator: validator.New(),
}

func (h *CustomerHandler) Create(w http.ResponseWriter, r *http.Request) {
	var input struct {
		AccountID            uuid.UUID `json:"account_id" validate:"required"`
		Name                 *string   `json:"name,omitempty"`
		Email                *string   `json:"email,omitempty"`
		Description          *string   `json:"description,omitempty"`
		BillingAddressLine1  *string   `json:"billing_address_line1,omitempty"`
		BillingAddressLine2  *string   `json:"billing_address_line2,omitempty"`
		BillingCity          *string   `json:"billing_city,omitempty"`
		BillingState         *string   `json:"billing_state,omitempty"`
		BillingPostalCode    *string   `json:"billing_postal_code,omitempty"`
		BillingCountry       *string   `json:"billing_country,omitempty"`
		ShippingAddressLine1 *string   `json:"shipping_address_line1,omitempty"`
		ShippingAddressLine2 *string   `json:"shipping_address_line2,omitempty"`
		ShippingCity         *string   `json:"shipping_city,omitempty"`
		ShippingState        *string   `json:"shipping_state,omitempty"`
		ShippingPostalCode   *string   `json:"shipping_postal_code,omitempty"`
		ShippingCountry      *string   `json:"shipping_country,omitempty"`
		PhoneNumber          *string   `json:"phone_number,omitempty"`
		Currency             *string   `json:"currency,omitempty" validate:"omitempty,len=3"`
	}

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		JsonResponse(w, http.StatusBadRequest, "Invalid request", err.Error())
		return
	}

	if err := h.Validator.Struct(input); err != nil {
		JsonResponse(w, http.StatusBadRequest, "Invalid request", err.Error())
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
		JsonResponse(w, http.StatusForbidden, "You are not authorized to create customers for this account", nil)
		return
	}

	customer := &Customer{
		ID:                   uuid.New(),
		UserID:               user.ID,
		AccountID:            input.AccountID,
		Name:                 input.Name,
		Email:                input.Email,
		Description:          input.Description,
		BillingAddressLine1:  input.BillingAddressLine1,
		BillingAddressLine2:  input.BillingAddressLine2,
		BillingCity:          input.BillingCity,
		BillingState:         input.BillingState,
		BillingPostalCode:    input.BillingPostalCode,
		BillingCountry:       input.BillingCountry,
		ShippingAddressLine1: input.ShippingAddressLine1,
		ShippingAddressLine2: input.ShippingAddressLine2,
		ShippingCity:         input.ShippingCity,
		ShippingState:        input.ShippingState,
		ShippingPostalCode:   input.ShippingPostalCode,
		ShippingCountry:      input.ShippingCountry,
		PhoneNumber:          input.PhoneNumber,
		Currency:             input.Currency,
	}

	createdCustomer, err := customerService.Create(customer)
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error creating customer", err.Error())
		return
	}

	JsonResponse(w, http.StatusCreated, "Customer created successfully", createdCustomer)
}

func (h *CustomerHandler) Update(w http.ResponseWriter, r *http.Request) {
	customerIDStr := chi.URLParam(r, "id")
	if customerIDStr == "" {
		JsonResponse(w, http.StatusBadRequest, "Customer ID is required", nil)
		return
	}

	customerID, err := uuid.Parse(customerIDStr)
	if err != nil {
		JsonResponse(w, http.StatusBadRequest, "Invalid customer ID", err.Error())
		return
	}

	user, err := GetUserFromContext(r.Context())
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error retrieving user", err.Error())
		return
	}

	existingCustomer, err := customerService.Get(customerID)
	if err != nil {
		JsonResponse(w, http.StatusNotFound, "Customer not found", err.Error())
		return
	}

	if existingCustomer.UserID != user.ID {
		JsonResponse(w, http.StatusForbidden, "You are not authorized to update this customer", nil)
		return
	}

	var input struct {
		Name                 *string `json:"name,omitempty"`
		Email                *string `json:"email,omitempty" validate:"omitempty,email"`
		Description          *string `json:"description,omitempty"`
		BillingAddressLine1  *string `json:"billing_address_line1,omitempty"`
		BillingAddressLine2  *string `json:"billing_address_line2,omitempty"`
		BillingCity          *string `json:"billing_city,omitempty"`
		BillingState         *string `json:"billing_state,omitempty"`
		BillingPostalCode    *string `json:"billing_postal_code,omitempty"`
		BillingCountry       *string `json:"billing_country,omitempty"`
		ShippingAddressLine1 *string `json:"shipping_address_line1,omitempty"`
		ShippingAddressLine2 *string `json:"shipping_address_line2,omitempty"`
		ShippingCity         *string `json:"shipping_city,omitempty"`
		ShippingState        *string `json:"shipping_state,omitempty"`
		ShippingPostalCode   *string `json:"shipping_postal_code,omitempty"`
		ShippingCountry      *string `json:"shipping_country,omitempty"`
		PhoneNumber          *string `json:"phone_number,omitempty"`
		Currency             *string `json:"currency,omitempty" validate:"omitempty,len=3"`
	}

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		JsonResponse(w, http.StatusBadRequest, "Invalid request", err.Error())
		return
	}

	if err := h.Validator.Struct(input); err != nil {
		JsonResponse(w, http.StatusBadRequest, "Invalid request", err.Error())
		return
	}

	customer := &Customer{
		ID:                   existingCustomer.ID,
		UserID:               existingCustomer.UserID,
		AccountID:            existingCustomer.AccountID,
		Name:                 input.Name,
		Email:                input.Email,
		Description:          input.Description,
		BillingAddressLine1:  input.BillingAddressLine1,
		BillingAddressLine2:  input.BillingAddressLine2,
		BillingCity:          input.BillingCity,
		BillingState:         input.BillingState,
		BillingPostalCode:    input.BillingPostalCode,
		BillingCountry:       input.BillingCountry,
		ShippingAddressLine1: input.ShippingAddressLine1,
		ShippingAddressLine2: input.ShippingAddressLine2,
		ShippingCity:         input.ShippingCity,
		ShippingState:        input.ShippingState,
		ShippingPostalCode:   input.ShippingPostalCode,
		ShippingCountry:      input.ShippingCountry,
		PhoneNumber:          input.PhoneNumber,
		Currency:             input.Currency,
	}

	err = customerService.Update(customer)
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error updating customer", err.Error())
		return
	}

	JsonResponse(w, http.StatusOK, "Customer updated successfully", customer)
}

func (h *CustomerHandler) Get(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		JsonResponse(w, http.StatusBadRequest, "Invalid customer ID", nil)
		return
	}

	customer, err := customerService.Get(id)
	if err != nil {
		JsonResponse(w, http.StatusNotFound, "Customer not found", err.Error())
		return
	}

	user, err := GetUserFromContext(r.Context())
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error retrieving user", err.Error())
		return
	}

	if customer.UserID != user.ID {
		JsonResponse(w, http.StatusForbidden, "You are not authorized to view this customer", nil)
		return
	}

	JsonResponse(w, http.StatusOK, "Customer retrieved successfully", customer)
}

func (h *CustomerHandler) GetAll(w http.ResponseWriter, r *http.Request) {
	user, err := GetUserFromContext(r.Context())
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error retrieving user", err.Error())
		return
	}

	customers, err := customerService.GetByUser(user.ID)
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error retrieving customers", err.Error())
		return
	}

	JsonResponse(w, http.StatusOK, "Customers retrieved successfully", customers)
}

func (h *CustomerHandler) GetByAccount(w http.ResponseWriter, r *http.Request) {
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
		JsonResponse(w, http.StatusForbidden, "You are not authorized to view customers for this account", nil)
		return
	}

	customers, err := customerService.GetByAccount(accountID)
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error retrieving customers", err.Error())
		return
	}

	JsonResponse(w, http.StatusOK, "Customers retrieved successfully", customers)
}

func (h *CustomerHandler) Delete(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		JsonResponse(w, http.StatusBadRequest, "Invalid customer ID", nil)
		return
	}

	customer, err := customerService.Get(id)
	if err != nil {
		JsonResponse(w, http.StatusNotFound, "Customer not found", err.Error())
		return
	}

	user, err := GetUserFromContext(r.Context())
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error retrieving user", err.Error())
		return
	}

	if customer.UserID != user.ID {
		JsonResponse(w, http.StatusForbidden, "You are not authorized to delete this customer", nil)
		return
	}

	err = customerService.Delete(id)
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error deleting customer", err.Error())
		return
	}

	JsonResponse(w, http.StatusOK, "Customer deleted successfully", nil)
}
