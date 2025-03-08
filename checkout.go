package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
)

type CheckoutState string

const (
	CheckoutStateOpen                CheckoutState = "open"
	CheckoutStatePendingConfirmation CheckoutState = "pending_confirmation"
	CheckoutStatePaid                CheckoutState = "paid"
	CheckoutStateUnderpaid           CheckoutState = "underpaid"
	CheckoutStateOverpaid            CheckoutState = "overpaid"
	CheckoutStateExpired             CheckoutState = "expired"
)

type Checkout struct {
	ID               uuid.UUID        `db:"id" json:"id"`
	UserID           uuid.UUID        `db:"user_id" json:"user_id"`
	AccountID        uuid.UUID        `db:"account_id" json:"account_id"`
	CustomerID       *uuid.UUID       `db:"customer_id" json:"customer_id,omitempty"`
	SubscriptionID   *uuid.UUID       `db:"subscription_id" json:"subscription_id,omitempty"`
	State            CheckoutState    `db:"state" json:"state"`
	Amount           int64            `db:"amount" json:"amount"`
	ReceivedAmount   int64            `db:"received_amount" json:"received_amount"`
	LightningInvoice *string          `db:"lightning_invoice" json:"lightning_invoice,omitempty"`
	BitcoinAddress   *string          `db:"bitcoin_address" json:"bitcoin_address,omitempty"`
	Metadata         *json.RawMessage `db:"metadata" json:"metadata,omitempty"`
	Items            *json.RawMessage `db:"items" json:"items,omitempty"`
	ExpiresAt        time.Time        `db:"expires_at" json:"expires_at"`
	CreatedAt        time.Time        `db:"created_at" json:"created_at"`
	UpdatedAt        time.Time        `db:"updated_at" json:"updated_at"`
	DeletedAt        *time.Time       `db:"deleted_at" json:"deleted_at,omitempty"`
}

type CheckoutCache struct {
	cache sync.Map
}

func (c *CheckoutCache) Get(id uuid.UUID) (*Checkout, bool) {
	value, ok := c.cache.Load(id)
	if !ok {
		return nil, false
	}
	checkout, ok := value.(*Checkout)
	return checkout, ok
}

func (c *CheckoutCache) Set(checkout *Checkout) {
	if checkout != nil {
		c.cache.Store(checkout.ID, checkout)
	}
}

func (c *CheckoutCache) Delete(id uuid.UUID) {
	c.cache.Delete(id)
}

type CheckoutRepository struct{}

func (r *CheckoutRepository) Create(checkout *Checkout) (*Checkout, error) {
	err := db.Get(checkout, `
		INSERT INTO checkouts (
			id, user_id, account_id, customer_id, subscription_id,
			state, amount, received_amount, lightning_invoice, bitcoin_address,
			metadata, items, expires_at, created_at, updated_at, deleted_at
		) VALUES (
			$1, $2, $3, $4, $5,
			$6, $7, $8, $9, $10,
			$11, $12, $13, $14, $15, $16
		) RETURNING *`,
		checkout.ID, checkout.UserID, checkout.AccountID, checkout.CustomerID, checkout.SubscriptionID,
		checkout.State, checkout.Amount, checkout.ReceivedAmount, checkout.LightningInvoice, checkout.BitcoinAddress,
		checkout.Metadata, checkout.Items, checkout.ExpiresAt, checkout.CreatedAt, checkout.UpdatedAt, checkout.DeletedAt)
	return checkout, err
}

func (r *CheckoutRepository) Get(id uuid.UUID) (*Checkout, error) {
	checkout := &Checkout{}
	err := db.Get(checkout, "SELECT * FROM checkouts WHERE id=$1 AND deleted_at IS NULL", id)
	return checkout, err
}

func (r *CheckoutRepository) GetByUser(userID uuid.UUID) ([]*Checkout, error) {
	checkouts := []*Checkout{}
	err := db.Select(&checkouts, "SELECT * FROM checkouts WHERE user_id=$1 AND deleted_at IS NULL ORDER BY created_at DESC", userID)
	return checkouts, err
}

func (r *CheckoutRepository) GetByAccount(accountID uuid.UUID) ([]*Checkout, error) {
	checkouts := []*Checkout{}
	err := db.Select(&checkouts, "SELECT * FROM checkouts WHERE account_id=$1 AND deleted_at IS NULL ORDER BY created_at DESC", accountID)
	return checkouts, err
}

func (r *CheckoutRepository) Update(checkout *Checkout) error {
	_, err := db.Exec(`
		UPDATE checkouts SET 
			state=$1, received_amount=$2, updated_at=$3
		WHERE id=$4`,
		checkout.State, checkout.ReceivedAmount, checkout.UpdatedAt, checkout.ID)
	return err
}

func (r *CheckoutRepository) MarkExpired() error {
	_, err := db.Exec(`
		UPDATE checkouts 
		SET state=$1, updated_at=$2
		WHERE state=$3 AND expires_at < $2 AND deleted_at IS NULL`,
		CheckoutStateExpired, time.Now(), CheckoutStateOpen)
	return err
}

func (r *CheckoutRepository) GetExpiredCheckouts() ([]*Checkout, error) {
	checkouts := []*Checkout{}
	err := db.Select(&checkouts, `
		SELECT * FROM checkouts 
		WHERE state=$1 AND expires_at < $2 AND deleted_at IS NULL 
		ORDER BY created_at DESC`,
		CheckoutStateOpen, time.Now())
	return checkouts, err
}

type CheckoutService struct {
	expirationTicker *time.Ticker
	done             chan bool
}

var checkoutRepository = &CheckoutRepository{}
var checkoutCache = &CheckoutCache{}
var checkoutService *CheckoutService

func NewCheckoutService() *CheckoutService {
	service := &CheckoutService{
		expirationTicker: time.NewTicker(5 * time.Minute),
		done:             make(chan bool),
	}

	go service.handleExpiredCheckouts()

	return service
}

func (s *CheckoutService) handleExpiredCheckouts() {
	for {
		select {
		case <-s.expirationTicker.C:
			expiredCheckouts, err := checkoutRepository.GetExpiredCheckouts()
			if err != nil {
				log.Printf("Error getting expired checkouts: %v", err)
				continue
			}

			for _, checkout := range expiredCheckouts {
				checkout.State = CheckoutStateExpired
				checkout.UpdatedAt = time.Now()

				if err := checkoutRepository.Update(checkout); err != nil {
					log.Printf("Error updating expired checkout %s: %v", checkout.ID, err)
					continue
				}

				checkoutCache.Set(checkout)
			}

		case <-s.done:
			s.expirationTicker.Stop()
			return
		}
	}
}

func (s *CheckoutService) Stop() {
	s.done <- true
}

func (s *CheckoutService) Create(checkout *Checkout) (*Checkout, error) {
	checkout.CreatedAt = time.Now()
	checkout.UpdatedAt = time.Now()
	checkout.State = CheckoutStateOpen

	if wallet, err := walletService.GetActiveWalletByAccount(checkout.AccountID); err == nil {
		expirySeconds := int64(30 * 60)
		description := fmt.Sprintf("Checkout #%s", checkout.ID.String())

		invoice, err := walletService.MakeInvoice(wallet.ID, checkout.Amount, description, expirySeconds)
		if err != nil {
			log.Printf("Failed to generate lightning invoice: %v", err)
		} else {
			checkout.LightningInvoice = &invoice
		}
	}

	createdCheckout, err := checkoutRepository.Create(checkout)
	if err == nil && createdCheckout != nil {
		checkoutCache.Set(createdCheckout)
	}
	return createdCheckout, err
}

func (s *CheckoutService) Get(id uuid.UUID) (*Checkout, error) {
	if cachedCheckout, found := checkoutCache.Get(id); found && cachedCheckout != nil {
		return cachedCheckout, nil
	}

	checkout, err := checkoutRepository.Get(id)
	if err == nil && checkout != nil {
		checkoutCache.Set(checkout)
	}
	return checkout, err
}

func (s *CheckoutService) UpdateState(id uuid.UUID, state CheckoutState, receivedAmount int64) error {
	checkout, err := s.Get(id)
	if err != nil {
		return err
	}

	checkout.State = state
	checkout.ReceivedAmount = receivedAmount
	checkout.UpdatedAt = time.Now()

	err = checkoutRepository.Update(checkout)
	if err == nil {
		checkoutCache.Set(checkout)
	}
	return err
}

func (s *CheckoutService) GetByUser(userID uuid.UUID) ([]*Checkout, error) {
	return checkoutRepository.GetByUser(userID)
}

func (s *CheckoutService) GetByAccount(accountID uuid.UUID) ([]*Checkout, error) {
	return checkoutRepository.GetByAccount(accountID)
}

type CheckoutHandler struct {
	Validator *validator.Validate
}

var checkoutHandler = &CheckoutHandler{
	Validator: validator.New(),
}

func (h *CheckoutHandler) Create(w http.ResponseWriter, r *http.Request) {
	var input struct {
		AccountID      uuid.UUID        `json:"account_id" validate:"required"`
		CustomerID     *uuid.UUID       `json:"customer_id"`
		SubscriptionID *uuid.UUID       `json:"subscription_id"`
		Amount         int64            `json:"amount" validate:"required,min=1"`
		Metadata       *json.RawMessage `json:"metadata"`
		Items          *json.RawMessage `json:"items"`
		ExpiryMinutes  int              `json:"expiry_minutes"`
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
		JsonResponse(w, http.StatusForbidden, "You are not authorized to create checkouts for this account", nil)
		return
	}

	if input.CustomerID != nil {
		customer, err := customerService.Get(*input.CustomerID)
		if err != nil {
			JsonResponse(w, http.StatusNotFound, "Customer not found", err.Error())
			return
		}

		if customer.UserID != user.ID || customer.AccountID != input.AccountID {
			JsonResponse(w, http.StatusForbidden, "You are not authorized to use this customer", nil)
			return
		}
	}

	if input.SubscriptionID != nil {
		subscription, err := subscriptionService.Get(*input.SubscriptionID)
		if err != nil {
			JsonResponse(w, http.StatusNotFound, "Subscription not found", err.Error())
			return
		}

		if subscription.UserID != user.ID || subscription.AccountID != input.AccountID {
			JsonResponse(w, http.StatusForbidden, "You are not authorized to use this subscription", nil)
			return
		}
	}

	expiryMinutes := 1440
	if input.ExpiryMinutes > 0 {
		expiryMinutes = input.ExpiryMinutes
	}

	checkout := &Checkout{
		ID:             uuid.New(),
		UserID:         user.ID,
		AccountID:      input.AccountID,
		CustomerID:     input.CustomerID,
		SubscriptionID: input.SubscriptionID,
		Amount:         input.Amount,
		Metadata:       input.Metadata,
		Items:          input.Items,
		ExpiresAt:      time.Now().Add(time.Duration(expiryMinutes) * time.Minute),
	}

	createdCheckout, err := checkoutService.Create(checkout)
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error creating checkout", err.Error())
		return
	}

	JsonResponse(w, http.StatusCreated, "Checkout created successfully", createdCheckout)
}

func (h *CheckoutHandler) Get(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		JsonResponse(w, http.StatusBadRequest, "Invalid checkout ID", err.Error())
		return
	}

	checkout, err := checkoutService.Get(id)
	if err != nil {
		JsonResponse(w, http.StatusNotFound, "Checkout not found", err.Error())
		return
	}

	JsonResponse(w, http.StatusOK, "Checkout retrieved successfully", checkout)
}

func init() {
	checkoutService = NewCheckoutService()
}

func IntegrateWithWalletListener() {
}
