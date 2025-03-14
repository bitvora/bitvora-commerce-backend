package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
)

type Subscription struct {
	ID               uuid.UUID       `db:"id" json:"id"`
	UserID           uuid.UUID       `db:"user_id" json:"user_id"`
	AccountID        uuid.UUID       `db:"account_id" json:"account_id"`
	CustomerID       uuid.UUID       `db:"customer_id" json:"customer_id"`
	ProductID        uuid.UUID       `db:"product_id" json:"product_id"`
	BillingStartDate time.Time       `db:"billing_start_date" json:"billing_start_date"`
	ActiveOnDate     time.Time       `db:"active_on_date" json:"active_on_date"`
	Metadata         json.RawMessage `db:"metadata" json:"metadata,omitempty"`
	NostrRelay       *string         `db:"nostr_relay" json:"nostr_relay,omitempty"`
	NostrPubkey      *string         `db:"nostr_pubkey" json:"nostr_pubkey,omitempty"`
	NostrSecret      *string         `db:"nostr_secret" json:"nostr_secret,omitempty"`
	CreatedAt        time.Time       `db:"created_at" json:"created_at"`
	UpdatedAt        time.Time       `db:"updated_at" json:"updated_at"`
	DeletedAt        *time.Time      `db:"deleted_at" json:"deleted_at,omitempty"`
}

type SubscriptionRepository struct{}
type SubscriptionService struct{}

var subscriptionRepository = &SubscriptionRepository{}
var subscriptionService = &SubscriptionService{}

func isValidJSON(data json.RawMessage) bool {
	if len(data) == 0 {
		return true // Allow empty JSON
	}
	var js json.RawMessage
	return json.Unmarshal(data, &js) == nil
}

func (r *SubscriptionRepository) Create(subscription *Subscription) (*Subscription, error) {
	// Log the Metadata field for debugging
	fmt.Printf("Creating subscription with Metadata: %s\n", string(subscription.Metadata))

	if !isValidJSON(subscription.Metadata) {
		return nil, fmt.Errorf("invalid JSON for Metadata")
	}

	err := db.Get(subscription, `
		INSERT INTO subscriptions (
			id, user_id, account_id, customer_id, product_id,
			billing_start_date, active_on_date, metadata,
			nostr_relay, nostr_pubkey, nostr_secret,
			created_at, updated_at, deleted_at
		) VALUES (
			$1, $2, $3, $4, $5,
			$6, $7, $8,
			$9, $10, $11,
			$12, $13, $14
		) RETURNING *`,
		subscription.ID, subscription.UserID, subscription.AccountID, subscription.CustomerID, subscription.ProductID,
		subscription.BillingStartDate, subscription.ActiveOnDate, subscription.Metadata,
		subscription.NostrRelay, subscription.NostrPubkey, subscription.NostrSecret,
		subscription.CreatedAt, subscription.UpdatedAt, subscription.DeletedAt)
	return subscription, err
}

func (r *SubscriptionRepository) Update(subscription *Subscription) error {
	_, err := db.Exec(`
		UPDATE subscriptions SET 
			billing_start_date=$1, active_on_date=$2, metadata=$3,
			nostr_relay=$4, nostr_pubkey=$5, nostr_secret=$6,
			updated_at=$7, deleted_at=$8
		WHERE id=$9`,
		subscription.BillingStartDate, subscription.ActiveOnDate, subscription.Metadata,
		subscription.NostrRelay, subscription.NostrPubkey, subscription.NostrSecret,
		subscription.UpdatedAt, subscription.DeletedAt, subscription.ID)
	return err
}

func (r *SubscriptionRepository) Get(id uuid.UUID) (*Subscription, error) {
	subscription := &Subscription{}
	err := db.Get(subscription, "SELECT * FROM subscriptions WHERE id=$1 AND deleted_at IS NULL", id)
	return subscription, err
}

func (r *SubscriptionRepository) GetByUser(userID uuid.UUID) ([]*Subscription, error) {
	subscriptions := []*Subscription{}
	err := db.Select(&subscriptions, "SELECT * FROM subscriptions WHERE user_id=$1 AND deleted_at IS NULL ORDER BY created_at DESC", userID)
	return subscriptions, err
}

func (r *SubscriptionRepository) GetByAccount(accountID uuid.UUID) ([]*Subscription, error) {
	subscriptions := []*Subscription{}
	err := db.Select(&subscriptions, "SELECT * FROM subscriptions WHERE account_id=$1 AND deleted_at IS NULL ORDER BY created_at DESC", accountID)
	return subscriptions, err
}

func (r *SubscriptionRepository) GetByCustomer(customerID uuid.UUID) ([]*Subscription, error) {
	subscriptions := []*Subscription{}
	err := db.Select(&subscriptions, "SELECT * FROM subscriptions WHERE customer_id=$1 AND deleted_at IS NULL ORDER BY created_at DESC", customerID)
	return subscriptions, err
}

func (r *SubscriptionRepository) GetByProduct(productID uuid.UUID) ([]*Subscription, error) {
	subscriptions := []*Subscription{}
	err := db.Select(&subscriptions, "SELECT * FROM subscriptions WHERE product_id=$1 AND deleted_at IS NULL ORDER BY created_at DESC", productID)
	return subscriptions, err
}

func (r *SubscriptionRepository) Delete(id uuid.UUID) error {
	_, err := db.Exec("UPDATE subscriptions SET deleted_at=$1 WHERE id=$2", time.Now(), id)
	return err
}

func (s *SubscriptionService) Create(subscription *Subscription) (*Subscription, error) {
	subscription.CreatedAt = time.Now()
	subscription.UpdatedAt = time.Now()
	return subscriptionRepository.Create(subscription)
}

func (s *SubscriptionService) Update(subscription *Subscription) error {
	subscription.UpdatedAt = time.Now()
	return subscriptionRepository.Update(subscription)
}

func (s *SubscriptionService) Get(id uuid.UUID) (*Subscription, error) {
	return subscriptionRepository.Get(id)
}

func (s *SubscriptionService) GetByUser(userID uuid.UUID) ([]*Subscription, error) {
	return subscriptionRepository.GetByUser(userID)
}

func (s *SubscriptionService) GetByAccount(accountID uuid.UUID) ([]*Subscription, error) {
	return subscriptionRepository.GetByAccount(accountID)
}

func (s *SubscriptionService) GetByCustomer(customerID uuid.UUID) ([]*Subscription, error) {
	return subscriptionRepository.GetByCustomer(customerID)
}

func (s *SubscriptionService) GetByProduct(productID uuid.UUID) ([]*Subscription, error) {
	return subscriptionRepository.GetByProduct(productID)
}

func (s *SubscriptionService) Delete(id uuid.UUID) error {
	return subscriptionRepository.Delete(id)
}

func (s *SubscriptionService) ProcessSubscriptionPayment(subscription *Subscription) error {
	if subscription.NostrPubkey == nil || subscription.NostrSecret == nil || subscription.NostrRelay == nil {
		return fmt.Errorf("subscription has no wallet connection")
	}

	product, err := productService.Get(subscription.ProductID)
	if err != nil {
		return fmt.Errorf("failed to get product: %w", err)
	}

	sellerWallet, err := walletService.GetActiveWalletByAccount(subscription.AccountID)
	if err != nil {
		return fmt.Errorf("failed to get seller wallet: %w", err)
	}

	expirySeconds := int64(60 * 60)
	description := fmt.Sprintf("Subscription payment for %s", product.Name)
	invoice, err := walletService.MakeInvoice(sellerWallet.ID, int64(product.Amount), description, expirySeconds)
	if err != nil {
		return fmt.Errorf("failed to create invoice: %w", err)
	}

	checkout := &Checkout{
		ID:               uuid.New(),
		UserID:           subscription.UserID,
		AccountID:        subscription.AccountID,
		CustomerID:       &subscription.CustomerID,
		SubscriptionID:   &subscription.ID,
		State:            CheckoutStateOpen,
		Amount:           int64(product.Amount),
		LightningInvoice: &invoice,
		ExpiresAt:        time.Now().Add(time.Hour),
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}

	_, err = checkoutService.Create(checkout)
	if err != nil {
		return fmt.Errorf("failed to create checkout: %w", err)
	}

	err = walletService.PayInvoiceWithConnection(
		*subscription.NostrPubkey,
		*subscription.NostrSecret,
		*subscription.NostrRelay,
		invoice,
	)

	if err != nil {
		checkout.State = CheckoutStateExpired
		checkout.UpdatedAt = time.Now()
		checkoutRepository.Update(checkout)
		return fmt.Errorf("failed to pay invoice: %w", err)
	}

	go func() {
		for i := 0; i < 20; i++ {
			time.Sleep(3 * time.Second)

			updatedCheckout, err := checkoutService.Get(checkout.ID)
			if err != nil {
				continue
			}

			if updatedCheckout.State != CheckoutStateOpen {
				break
			}
		}
	}()

	return nil
}

func InitSubscriptionScheduler() {
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				processSubscriptionRenewals()
			}
		}
	}()
}

func processSubscriptionRenewals() {
	// Query for subscriptions to process
	// For now, we can't implement full renewal logic without a field to track next bill date
	// This would require a database schema change
}

type SubscriptionHandler struct {
	Validator *validator.Validate
}

var subscriptionHandler = &SubscriptionHandler{
	Validator: validator.New(),
}

func (h *SubscriptionHandler) Create(w http.ResponseWriter, r *http.Request) {
	var input struct {
		AccountID        uuid.UUID       `json:"account_id" validate:"required"`
		CustomerID       uuid.UUID       `json:"customer_id" validate:"required"`
		ProductID        uuid.UUID       `json:"product_id" validate:"required"`
		BillingStartDate *time.Time      `json:"billing_start_date"`
		ActiveOnDate     *time.Time      `json:"active_on_date"`
		Metadata         json.RawMessage `json:"metadata,omitempty"`
		NostrRelay       *string         `json:"nostr_relay,omitempty"`
		NostrPubkey      *string         `json:"nostr_pubkey,omitempty"`
		NostrSecret      *string         `json:"nostr_secret,omitempty"`
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
		JsonResponse(w, http.StatusForbidden, "You are not authorized to create subscriptions for this account", nil)
		return
	}

	customer, err := customerService.Get(input.CustomerID)
	if err != nil {
		JsonResponse(w, http.StatusBadRequest, "Invalid customer ID", err.Error())
		return
	}
	if customer.UserID != user.ID || customer.AccountID != input.AccountID {
		JsonResponse(w, http.StatusForbidden, "You are not authorized to use this customer", nil)
		return
	}

	product, err := productService.Get(input.ProductID)
	if err != nil {
		JsonResponse(w, http.StatusBadRequest, "Invalid product ID", err.Error())
		return
	}
	if product.UserID != user.ID || product.AccountID != input.AccountID {
		JsonResponse(w, http.StatusForbidden, "You are not authorized to use this product", nil)
		return
	}
	if !product.IsRecurring {
		JsonResponse(w, http.StatusBadRequest, "Subscriptions can only be created for recurring products", nil)
		return
	}

	now := time.Now()
	billingStartDate := now
	if input.BillingStartDate != nil {
		billingStartDate = *input.BillingStartDate
	}

	activeOnDate := now
	if input.ActiveOnDate != nil {
		activeOnDate = *input.ActiveOnDate
	}

	subscription := &Subscription{
		ID:               uuid.New(),
		UserID:           user.ID,
		AccountID:        input.AccountID,
		CustomerID:       input.CustomerID,
		ProductID:        input.ProductID,
		BillingStartDate: billingStartDate,
		ActiveOnDate:     activeOnDate,
		Metadata:         input.Metadata,
		NostrRelay:       input.NostrRelay,
		NostrPubkey:      input.NostrPubkey,
		NostrSecret:      input.NostrSecret,
	}

	createdSubscription, err := subscriptionService.Create(subscription)
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error creating subscription", err.Error())
		return
	}

	JsonResponse(w, http.StatusCreated, "Subscription created successfully", createdSubscription)
}

func (h *SubscriptionHandler) Update(w http.ResponseWriter, r *http.Request) {
	subscriptionIDStr := chi.URLParam(r, "id")
	if subscriptionIDStr == "" {
		JsonResponse(w, http.StatusBadRequest, "Subscription ID is required", nil)
		return
	}

	subscriptionID, err := uuid.Parse(subscriptionIDStr)
	if err != nil {
		JsonResponse(w, http.StatusBadRequest, "Invalid subscription ID", err.Error())
		return
	}

	user, err := GetUserFromContext(r.Context())
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error retrieving user", err.Error())
		return
	}

	existingSubscription, err := subscriptionService.Get(subscriptionID)
	if err != nil {
		JsonResponse(w, http.StatusNotFound, "Subscription not found", err.Error())
		return
	}

	if existingSubscription.UserID != user.ID {
		JsonResponse(w, http.StatusForbidden, "You are not authorized to update this subscription", nil)
		return
	}

	var input struct {
		BillingStartDate *time.Time      `json:"billing_start_date"`
		ActiveOnDate     *time.Time      `json:"active_on_date"`
		Metadata         json.RawMessage `json:"metadata,omitempty"`
		NostrRelay       *string         `json:"nostr_relay,omitempty"`
		NostrPubkey      *string         `json:"nostr_pubkey,omitempty"`
		NostrSecret      *string         `json:"nostr_secret,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		JsonResponse(w, http.StatusBadRequest, "Invalid request", err.Error())
		return
	}

	if input.BillingStartDate != nil {
		existingSubscription.BillingStartDate = *input.BillingStartDate
	}

	if input.ActiveOnDate != nil {
		existingSubscription.ActiveOnDate = *input.ActiveOnDate
	}

	if input.Metadata != nil {
		existingSubscription.Metadata = input.Metadata
	}

	existingSubscription.NostrRelay = input.NostrRelay
	existingSubscription.NostrPubkey = input.NostrPubkey
	existingSubscription.NostrSecret = input.NostrSecret

	err = subscriptionService.Update(existingSubscription)
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error updating subscription", err.Error())
		return
	}

	JsonResponse(w, http.StatusOK, "Subscription updated successfully", existingSubscription)
}

func (h *SubscriptionHandler) Get(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		JsonResponse(w, http.StatusBadRequest, "Invalid subscription ID", nil)
		return
	}

	subscription, err := subscriptionService.Get(id)
	if err != nil {
		JsonResponse(w, http.StatusNotFound, "Subscription not found", err.Error())
		return
	}

	user, err := GetUserFromContext(r.Context())
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error retrieving user", err.Error())
		return
	}

	if subscription.UserID != user.ID {
		JsonResponse(w, http.StatusForbidden, "You are not authorized to view this subscription", nil)
		return
	}

	JsonResponse(w, http.StatusOK, "Subscription retrieved successfully", subscription)
}

func (h *SubscriptionHandler) GetAll(w http.ResponseWriter, r *http.Request) {
	user, err := GetUserFromContext(r.Context())
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error retrieving user", err.Error())
		return
	}

	subscriptions, err := subscriptionService.GetByUser(user.ID)
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error retrieving subscriptions", err.Error())
		return
	}

	JsonResponse(w, http.StatusOK, "Subscriptions retrieved successfully", subscriptions)
}

func (h *SubscriptionHandler) GetByAccount(w http.ResponseWriter, r *http.Request) {
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
		JsonResponse(w, http.StatusForbidden, "You are not authorized to view subscriptions for this account", nil)
		return
	}

	subscriptions, err := subscriptionService.GetByAccount(accountID)
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error retrieving subscriptions", err.Error())
		return
	}

	JsonResponse(w, http.StatusOK, "Subscriptions retrieved successfully", subscriptions)
}

func (h *SubscriptionHandler) GetByCustomer(w http.ResponseWriter, r *http.Request) {
	customerIDStr := chi.URLParam(r, "customerId")
	customerID, err := uuid.Parse(customerIDStr)
	if err != nil {
		JsonResponse(w, http.StatusBadRequest, "Invalid customer ID", nil)
		return
	}

	user, err := GetUserFromContext(r.Context())
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error retrieving user", err.Error())
		return
	}

	customer, err := customerService.Get(customerID)
	if err != nil {
		JsonResponse(w, http.StatusNotFound, "Customer not found", err.Error())
		return
	}
	if customer.UserID != user.ID {
		JsonResponse(w, http.StatusForbidden, "You are not authorized to view subscriptions for this customer", nil)
		return
	}

	subscriptions, err := subscriptionService.GetByCustomer(customerID)
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error retrieving subscriptions", err.Error())
		return
	}

	JsonResponse(w, http.StatusOK, "Subscriptions retrieved successfully", subscriptions)
}

func (h *SubscriptionHandler) GetByProduct(w http.ResponseWriter, r *http.Request) {
	productIDStr := chi.URLParam(r, "productId")
	productID, err := uuid.Parse(productIDStr)
	if err != nil {
		JsonResponse(w, http.StatusBadRequest, "Invalid product ID", nil)
		return
	}

	user, err := GetUserFromContext(r.Context())
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error retrieving user", err.Error())
		return
	}

	product, err := productService.Get(productID)
	if err != nil {
		JsonResponse(w, http.StatusNotFound, "Product not found", err.Error())
		return
	}
	if product.UserID != user.ID {
		JsonResponse(w, http.StatusForbidden, "You are not authorized to view subscriptions for this product", nil)
		return
	}

	subscriptions, err := subscriptionService.GetByProduct(productID)
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error retrieving subscriptions", err.Error())
		return
	}

	JsonResponse(w, http.StatusOK, "Subscriptions retrieved successfully", subscriptions)
}

func (h *SubscriptionHandler) Delete(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		JsonResponse(w, http.StatusBadRequest, "Invalid subscription ID", nil)
		return
	}

	subscription, err := subscriptionService.Get(id)
	if err != nil {
		JsonResponse(w, http.StatusNotFound, "Subscription not found", err.Error())
		return
	}

	user, err := GetUserFromContext(r.Context())
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error retrieving user", err.Error())
		return
	}

	if subscription.UserID != user.ID {
		JsonResponse(w, http.StatusForbidden, "You are not authorized to delete this subscription", nil)
		return
	}

	err = subscriptionService.Delete(id)
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error deleting subscription", err.Error())
		return
	}

	JsonResponse(w, http.StatusOK, "Subscription deleted successfully", nil)
}
