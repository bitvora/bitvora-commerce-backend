package main

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
)

type PaymentLink struct {
	ID            uuid.UUID        `db:"id" json:"id"`
	UserID        uuid.UUID        `db:"user_id" json:"user_id"`
	AccountID     uuid.UUID        `db:"account_id" json:"account_id"`
	Amount        float64          `db:"amount" json:"amount"`
	Currency      string           `db:"currency" json:"currency"`
	Metadata      *json.RawMessage `db:"metadata" json:"metadata,omitempty"`
	Items         *json.RawMessage `db:"items" json:"items,omitempty"`
	ExpiryMinutes int              `db:"expiry_minutes" json:"expiry_minutes"`
	CreatedAt     time.Time        `db:"created_at" json:"created_at"`
	UpdatedAt     time.Time        `db:"updated_at" json:"updated_at"`
	DeletedAt     *time.Time       `db:"deleted_at" json:"deleted_at,omitempty"`
}

type PaymentLinkCache struct {
	cache sync.Map
}

func (c *PaymentLinkCache) Get(id uuid.UUID) (*PaymentLink, bool) {
	value, ok := c.cache.Load(id)
	if !ok {
		return nil, false
	}
	paymentLink, ok := value.(*PaymentLink)
	return paymentLink, ok
}

func (c *PaymentLinkCache) Set(paymentLink *PaymentLink) {
	if paymentLink != nil {
		c.cache.Store(paymentLink.ID, paymentLink)
	}
}

func (c *PaymentLinkCache) Delete(id uuid.UUID) {
	c.cache.Delete(id)
}

type PaymentLinkRepository struct{}

func (r *PaymentLinkRepository) Create(paymentLink *PaymentLink) (*PaymentLink, error) {
	err := db.Get(paymentLink, `
		INSERT INTO payment_links (
			id, user_id, account_id, amount, currency,
			metadata, items, expiry_minutes, created_at, updated_at, deleted_at
		) VALUES (
			$1, $2, $3, $4, $5, $6,
			$7, $8, $9, $10, $11
		) RETURNING *`,
		paymentLink.ID, paymentLink.UserID, paymentLink.AccountID, paymentLink.Amount, paymentLink.Currency,
		paymentLink.Metadata, paymentLink.Items, paymentLink.ExpiryMinutes,
		paymentLink.CreatedAt, paymentLink.UpdatedAt, paymentLink.DeletedAt)
	return paymentLink, err
}

func (r *PaymentLinkRepository) Get(id uuid.UUID) (*PaymentLink, error) {
	paymentLink := &PaymentLink{}
	err := db.Get(paymentLink, "SELECT * FROM payment_links WHERE id=$1 AND deleted_at IS NULL", id)
	return paymentLink, err
}

func (r *PaymentLinkRepository) GetByUser(userID uuid.UUID) ([]*PaymentLink, error) {
	paymentLinks := []*PaymentLink{}
	err := db.Select(&paymentLinks, "SELECT * FROM payment_links WHERE user_id=$1 AND deleted_at IS NULL ORDER BY created_at DESC", userID)
	return paymentLinks, err
}

func (r *PaymentLinkRepository) GetByAccount(accountID uuid.UUID) ([]*PaymentLink, error) {
	paymentLinks := []*PaymentLink{}
	err := db.Select(&paymentLinks, "SELECT * FROM payment_links WHERE account_id=$1 AND deleted_at IS NULL ORDER BY created_at DESC", accountID)
	return paymentLinks, err
}

func (r *PaymentLinkRepository) Update(paymentLink *PaymentLink) error {
	_, err := db.Exec(`
		UPDATE payment_links SET 
			amount=$1, currency=$2, metadata=$3, items=$4, 
			expiry_minutes=$5, updated_at=$6
		WHERE id=$7`,
		paymentLink.Amount, paymentLink.Currency, paymentLink.Metadata, paymentLink.Items,
		paymentLink.ExpiryMinutes, paymentLink.UpdatedAt, paymentLink.ID)
	return err
}

func (r *PaymentLinkRepository) Delete(id uuid.UUID) error {
	_, err := db.Exec("UPDATE payment_links SET deleted_at=$1 WHERE id=$2", time.Now(), id)
	return err
}

type PaymentLinkService struct{}

var paymentLinkRepository = &PaymentLinkRepository{}
var paymentLinkCache = &PaymentLinkCache{}
var paymentLinkService *PaymentLinkService

func NewPaymentLinkService() *PaymentLinkService {
	return &PaymentLinkService{}
}

func (s *PaymentLinkService) Create(paymentLink *PaymentLink) (*PaymentLink, error) {
	paymentLink.CreatedAt = time.Now()
	paymentLink.UpdatedAt = time.Now()

	createdPaymentLink, err := paymentLinkRepository.Create(paymentLink)
	if err == nil && createdPaymentLink != nil {
		paymentLinkCache.Set(createdPaymentLink)
	}
	return createdPaymentLink, err
}

func (s *PaymentLinkService) Get(id uuid.UUID) (*PaymentLink, error) {
	if cachedPaymentLink, found := paymentLinkCache.Get(id); found && cachedPaymentLink != nil {
		return cachedPaymentLink, nil
	}

	paymentLink, err := paymentLinkRepository.Get(id)
	if err == nil && paymentLink != nil {
		paymentLinkCache.Set(paymentLink)
	}
	return paymentLink, err
}

func (s *PaymentLinkService) Update(paymentLink *PaymentLink) error {
	paymentLink.UpdatedAt = time.Now()
	err := paymentLinkRepository.Update(paymentLink)
	if err == nil {
		paymentLinkCache.Set(paymentLink)
	}
	return err
}

func (s *PaymentLinkService) Delete(id uuid.UUID) error {
	err := paymentLinkRepository.Delete(id)
	if err == nil {
		paymentLinkCache.Delete(id)
	}
	return err
}

func (s *PaymentLinkService) GetByUser(userID uuid.UUID) ([]*PaymentLink, error) {
	return paymentLinkRepository.GetByUser(userID)
}

func (s *PaymentLinkService) GetByAccount(accountID uuid.UUID) ([]*PaymentLink, error) {
	return paymentLinkRepository.GetByAccount(accountID)
}

func (s *PaymentLinkService) CreateCheckoutFromLink(paymentLinkID uuid.UUID) (*Checkout, error) {
	paymentLink, err := s.Get(paymentLinkID)
	if err != nil {
		return nil, err
	}

	// Get current rates at checkout creation time
	rates := fiatRateService.GetRates()
	ratesJSON, err := json.Marshal(rates)
	if err != nil {
		return nil, err
	}

	// Convert amount to int64 based on currency
	var amountInSats int64
	if paymentLink.Currency != "sats" && paymentLink.Currency != "btc" {
		sats, err := fiatRateService.FiatToSatoshis(paymentLink.Amount, paymentLink.Currency)
		if err != nil {
			return nil, err
		}
		amountInSats = sats
	} else {
		if paymentLink.Currency == "btc" {
			amountInSats = int64(paymentLink.Amount * 100000000)
		} else {
			amountInSats = int64(paymentLink.Amount)
		}
	}

	checkout := &Checkout{
		ID:        uuid.New(),
		UserID:    paymentLink.UserID,
		AccountID: paymentLink.AccountID,
		Amount:    amountInSats, // Use converted amount
		Metadata:  paymentLink.Metadata,
		Items:     paymentLink.Items,
		Rates:     ratesJSON,
		ExpiresAt: time.Now().Add(time.Duration(paymentLink.ExpiryMinutes) * time.Minute),
	}

	return checkoutService.Create(checkout)
}

type PaymentLinkHandler struct {
	Validator *validator.Validate
}

var paymentLinkHandler = &PaymentLinkHandler{
	Validator: validator.New(),
}

func (h *PaymentLinkHandler) Create(w http.ResponseWriter, r *http.Request) {
	var input struct {
		AccountID     uuid.UUID        `json:"account_id" validate:"required"`
		Amount        float64          `json:"amount" validate:"required,gte=0"`
		Currency      string           `json:"currency" validate:"required"`
		Metadata      *json.RawMessage `json:"metadata"`
		Items         *json.RawMessage `json:"items"`
		ExpiryMinutes int              `json:"expiry_minutes"`
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
		JsonResponse(w, http.StatusNotFound, "Account not found", err.Error())
		return
	}

	if account.UserID != user.ID {
		JsonResponse(w, http.StatusForbidden, "You are not authorized to create payment links for this account", nil)
		return
	}

	expiryMinutes := 1440
	if input.ExpiryMinutes > 0 {
		expiryMinutes = input.ExpiryMinutes
	}
	// Create payment link without rates
	paymentLink := &PaymentLink{
		ID:            uuid.New(),
		UserID:        user.ID,
		AccountID:     input.AccountID,
		Amount:        input.Amount,
		Currency:      input.Currency,
		Metadata:      input.Metadata,
		Items:         input.Items,
		ExpiryMinutes: expiryMinutes,
	}

	createdPaymentLink, err := paymentLinkService.Create(paymentLink)
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error creating payment link", err.Error())
		return
	}

	JsonResponse(w, http.StatusCreated, "Payment link created successfully", createdPaymentLink)
}

func (h *PaymentLinkHandler) Get(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		JsonResponse(w, http.StatusBadRequest, "Invalid payment link ID", err.Error())
		return
	}

	user, err := GetUserFromContext(r.Context())
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error retrieving user", err.Error())
		return
	}

	paymentLink, err := paymentLinkService.Get(id)
	if err != nil {
		JsonResponse(w, http.StatusNotFound, "Payment link not found", err.Error())
		return
	}

	if paymentLink.UserID != user.ID {
		JsonResponse(w, http.StatusForbidden, "You are not authorized to access this payment link", nil)
		return
	}

	JsonResponse(w, http.StatusOK, "Payment link retrieved successfully", paymentLink)
}

func (h *PaymentLinkHandler) Update(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		JsonResponse(w, http.StatusBadRequest, "Invalid payment link ID", err.Error())
		return
	}

	var input struct {
		Amount        float64          `json:"amount" validate:"required,gte=0"`
		Currency      string           `json:"currency" validate:"required"`
		Metadata      *json.RawMessage `json:"metadata"`
		Items         *json.RawMessage `json:"items"`
		ExpiryMinutes int              `json:"expiry_minutes"`
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

	paymentLink, err := paymentLinkService.Get(id)
	if err != nil {
		JsonResponse(w, http.StatusNotFound, "Payment link not found", err.Error())
		return
	}

	if paymentLink.UserID != user.ID {
		JsonResponse(w, http.StatusForbidden, "You are not authorized to update this payment link", nil)
		return
	}

	// Update the payment link fields
	paymentLink.Amount = input.Amount
	paymentLink.Currency = input.Currency
	paymentLink.Metadata = input.Metadata
	paymentLink.Items = input.Items
	if input.ExpiryMinutes > 0 {
		paymentLink.ExpiryMinutes = input.ExpiryMinutes
	}

	err = paymentLinkService.Update(paymentLink)
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error updating payment link", err.Error())
		return
	}

	JsonResponse(w, http.StatusOK, "Payment link updated successfully", paymentLink)
}

func (h *PaymentLinkHandler) Delete(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		JsonResponse(w, http.StatusBadRequest, "Invalid payment link ID", err.Error())
		return
	}

	user, err := GetUserFromContext(r.Context())
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error retrieving user", err.Error())
		return
	}

	paymentLink, err := paymentLinkService.Get(id)
	if err != nil {
		JsonResponse(w, http.StatusNotFound, "Payment link not found", err.Error())
		return
	}

	if paymentLink.UserID != user.ID {
		JsonResponse(w, http.StatusForbidden, "You are not authorized to delete this payment link", nil)
		return
	}

	err = paymentLinkService.Delete(id)
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error deleting payment link", err.Error())
		return
	}

	JsonResponse(w, http.StatusOK, "Payment link deleted successfully", nil)
}

func (h *PaymentLinkHandler) List(w http.ResponseWriter, r *http.Request) {
	user, err := GetUserFromContext(r.Context())
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error retrieving user", err.Error())
		return
	}

	paymentLinks, err := paymentLinkService.GetByUser(user.ID)
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error retrieving payment links", err.Error())
		return
	}

	JsonResponse(w, http.StatusOK, "Payment links retrieved successfully", paymentLinks)
}

func (h *PaymentLinkHandler) ListByAccount(w http.ResponseWriter, r *http.Request) {
	accountIDStr := chi.URLParam(r, "accountID")
	accountID, err := uuid.Parse(accountIDStr)
	if err != nil {
		JsonResponse(w, http.StatusBadRequest, "Invalid account ID", err.Error())
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
		JsonResponse(w, http.StatusForbidden, "You are not authorized to access payment links for this account", nil)
		return
	}

	paymentLinks, err := paymentLinkService.GetByAccount(accountID)
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error retrieving payment links", err.Error())
		return
	}

	JsonResponse(w, http.StatusOK, "Payment links retrieved successfully", paymentLinks)
}

func (h *PaymentLinkHandler) PublicLinkHandler(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		JsonResponse(w, http.StatusBadRequest, "Invalid payment link ID", err.Error())
		return
	}

	checkout, err := paymentLinkService.CreateCheckoutFromLink(id)
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error creating checkout", err.Error())
		return
	}

	JsonResponse(w, http.StatusOK, "Checkout created from payment link", checkout)
}
