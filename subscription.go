package main

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
)

type Subscription struct {
	ID                    uuid.UUID       `db:"id" json:"id"`
	UserID                uuid.UUID       `db:"user_id" json:"user_id"`
	AccountID             uuid.UUID       `db:"account_id" json:"account_id"`
	CustomerID            uuid.UUID       `db:"customer_id" json:"customer_id"`
	ProductID             uuid.UUID       `db:"product_id" json:"product_id"`
	BillingStartDate      time.Time       `db:"billing_start_date" json:"billing_start_date"`
	ActiveOnDate          time.Time       `db:"active_on_date" json:"active_on_date"`
	Status                string          `db:"status" json:"status"`
	NextBillingDate       time.Time       `db:"next_billing_date" json:"next_billing_date"`
	LastPaymentDate       *time.Time      `db:"last_payment_date" json:"last_payment_date,omitempty"`
	LastPaymentStatus     *string         `db:"last_payment_status" json:"last_payment_status,omitempty"`
	FailedPaymentAttempts int             `db:"failed_payment_attempts" json:"failed_payment_attempts"`
	BillingIntervalHours  *int            `db:"billing_interval_hours" json:"billing_interval_hours,omitempty"`
	Metadata              json.RawMessage `db:"metadata" json:"metadata,omitempty"`
	NostrRelay            *string         `db:"nostr_relay" json:"nostr_relay,omitempty"`
	NostrPubkey           *string         `db:"nostr_pubkey" json:"nostr_pubkey,omitempty"`
	NostrSecret           *string         `db:"nostr_secret" json:"nostr_secret,omitempty"`
	CreatedAt             time.Time       `db:"created_at" json:"created_at"`
	UpdatedAt             time.Time       `db:"updated_at" json:"updated_at"`
	DeletedAt             *time.Time      `db:"deleted_at" json:"deleted_at,omitempty"`
}

type SubscriptionRepository struct{}
type SubscriptionService struct{}

var subscriptionRepository = &SubscriptionRepository{}
var subscriptionService = &SubscriptionService{}

const (
	SubscriptionStatusActive    = "active"
	SubscriptionStatusSuspended = "suspended"
	SubscriptionStatusCancelled = "cancelled"

	// Payment status constants
	PaymentStatusSuccess = "success"
	PaymentStatusFailed  = "failed"
	PaymentStatusPending = "pending"

	// Max payment retry attempts before suspension
	MaxPaymentRetryAttempts = 3

	// Notification event constants for subscriptions
	NotificationEventSubscriptionPaymentSuccessful = "subscription.payment_successful"
	NotificationEventSubscriptionPaymentFailed     = "subscription.payment_failed"
	NotificationEventSubscriptionSuspended         = "subscription.suspended"
	NotificationEventSubscriptionReactivated       = "subscription.reactivated"
	NotificationEventSubscriptionCanceled          = "subscription.canceled"

	// Webhook event constants for subscriptions
	WebhookEventSubscriptionPaymentSuccessful = "subscription.payment_successful"
	WebhookEventSubscriptionPaymentFailed     = "subscription.payment_failed"
	WebhookEventSubscriptionSuspended         = "subscription.suspended"
	WebhookEventSubscriptionReactivated       = "subscription.reactivated"
	WebhookEventSubscriptionCanceled          = "subscription.canceled"

	// Add constants for retry timing logic
	MinRetryWaitMinutes       = 5
	MaxRetryWaitPercentage    = 0.25
	DefaultRetryIntervalHours = 24
)

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

	// Store original secret to restore after database operation
	var originalSecret *string
	if subscription.NostrSecret != nil {
		originalSecret = subscription.NostrSecret

		// Encrypt the nostr secret before storing
		encryptedSecret, err := encrypt(*subscription.NostrSecret)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt nostr secret: %w", err)
		}
		subscription.NostrSecret = &encryptedSecret
	}

	err := db.Get(subscription, `
		INSERT INTO subscriptions (
			id, user_id, account_id, customer_id, product_id,
			billing_start_date, active_on_date, status, next_billing_date, 
			last_payment_date, last_payment_status, failed_payment_attempts, 
			billing_interval_hours, metadata, nostr_relay, nostr_pubkey, 
			nostr_secret, created_at, updated_at, deleted_at
		) VALUES (
			$1, $2, $3, $4, $5,
			$6, $7, $8, $9, $10,
			$11, $12, $13, $14, $15,
			$16, $17, $18, $19, $20
		) RETURNING *`,
		subscription.ID, subscription.UserID, subscription.AccountID, subscription.CustomerID, subscription.ProductID,
		subscription.BillingStartDate, subscription.ActiveOnDate, subscription.Status, subscription.NextBillingDate,
		subscription.LastPaymentDate, subscription.LastPaymentStatus, subscription.FailedPaymentAttempts,
		subscription.BillingIntervalHours, subscription.Metadata, subscription.NostrRelay, subscription.NostrPubkey,
		subscription.NostrSecret, subscription.CreatedAt, subscription.UpdatedAt, subscription.DeletedAt)

	// Restore original secret if creation was successful
	if err == nil && originalSecret != nil {
		subscription.NostrSecret = originalSecret
	}

	return subscription, err
}

func (r *SubscriptionRepository) Update(subscription *Subscription) error {
	// Store original secret to restore after database operation
	var originalSecret *string
	if subscription.NostrSecret != nil {
		originalSecret = subscription.NostrSecret

		// Encrypt the nostr secret before storing
		encryptedSecret, err := encrypt(*subscription.NostrSecret)
		if err != nil {
			return fmt.Errorf("failed to encrypt nostr secret: %w", err)
		}
		subscription.NostrSecret = &encryptedSecret
	}

	_, err := db.Exec(`
		UPDATE subscriptions SET 
			billing_start_date=$1, active_on_date=$2, status=$3, 
			next_billing_date=$4, last_payment_date=$5, last_payment_status=$6,
			failed_payment_attempts=$7, billing_interval_hours=$8, metadata=$9,
			nostr_relay=$10, nostr_pubkey=$11, nostr_secret=$12,
			updated_at=$13, deleted_at=$14
		WHERE id=$15`,
		subscription.BillingStartDate, subscription.ActiveOnDate, subscription.Status,
		subscription.NextBillingDate, subscription.LastPaymentDate, subscription.LastPaymentStatus,
		subscription.FailedPaymentAttempts, subscription.BillingIntervalHours, subscription.Metadata,
		subscription.NostrRelay, subscription.NostrPubkey, subscription.NostrSecret,
		subscription.UpdatedAt, subscription.DeletedAt, subscription.ID)

	// Restore original secret if update was successful
	if err == nil && originalSecret != nil {
		subscription.NostrSecret = originalSecret
	}

	return err
}

func (r *SubscriptionRepository) Get(id uuid.UUID) (*Subscription, error) {
	subscription := &Subscription{}
	err := db.Get(subscription, "SELECT * FROM subscriptions WHERE id=$1 AND deleted_at IS NULL", id)
	if err != nil {
		return nil, err
	}

	// Decrypt the nostr secret if it exists
	if subscription.NostrSecret != nil && *subscription.NostrSecret != "" {
		decryptedSecret, err := decrypt(*subscription.NostrSecret)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt nostr secret: %w", err)
		}
		subscription.NostrSecret = &decryptedSecret
	}

	return subscription, nil
}

func (r *SubscriptionRepository) GetByUser(userID uuid.UUID) ([]*Subscription, error) {
	subscriptions := []*Subscription{}
	err := db.Select(&subscriptions, "SELECT * FROM subscriptions WHERE user_id=$1 AND deleted_at IS NULL ORDER BY created_at DESC", userID)
	if err != nil {
		return nil, err
	}

	// Decrypt the nostr secret for each subscription
	for _, subscription := range subscriptions {
		if subscription.NostrSecret != nil && *subscription.NostrSecret != "" {
			decryptedSecret, err := decrypt(*subscription.NostrSecret)
			if err != nil {
				return nil, fmt.Errorf("failed to decrypt nostr secret: %w", err)
			}
			subscription.NostrSecret = &decryptedSecret
		}
	}

	return subscriptions, nil
}

func (r *SubscriptionRepository) GetByAccount(accountID uuid.UUID) ([]*Subscription, error) {
	subscriptions := []*Subscription{}
	err := db.Select(&subscriptions, "SELECT * FROM subscriptions WHERE account_id=$1 AND deleted_at IS NULL ORDER BY created_at DESC", accountID)
	if err != nil {
		return nil, err
	}

	// Decrypt the nostr secret for each subscription
	for _, subscription := range subscriptions {
		if subscription.NostrSecret != nil && *subscription.NostrSecret != "" {
			decryptedSecret, err := decrypt(*subscription.NostrSecret)
			if err != nil {
				return nil, fmt.Errorf("failed to decrypt nostr secret: %w", err)
			}
			subscription.NostrSecret = &decryptedSecret
		}
	}

	return subscriptions, nil
}

func (r *SubscriptionRepository) GetByCustomer(customerID uuid.UUID) ([]*Subscription, error) {
	subscriptions := []*Subscription{}
	err := db.Select(&subscriptions, "SELECT * FROM subscriptions WHERE customer_id=$1 AND deleted_at IS NULL ORDER BY created_at DESC", customerID)
	if err != nil {
		return nil, err
	}

	// Decrypt the nostr secret for each subscription
	for _, subscription := range subscriptions {
		if subscription.NostrSecret != nil && *subscription.NostrSecret != "" {
			decryptedSecret, err := decrypt(*subscription.NostrSecret)
			if err != nil {
				return nil, fmt.Errorf("failed to decrypt nostr secret: %w", err)
			}
			subscription.NostrSecret = &decryptedSecret
		}
	}

	return subscriptions, nil
}

func (r *SubscriptionRepository) GetByProduct(productID uuid.UUID) ([]*Subscription, error) {
	subscriptions := []*Subscription{}
	err := db.Select(&subscriptions, "SELECT * FROM subscriptions WHERE product_id=$1 AND deleted_at IS NULL ORDER BY created_at DESC", productID)
	if err != nil {
		return nil, err
	}

	// Decrypt the nostr secret for each subscription
	for _, subscription := range subscriptions {
		if subscription.NostrSecret != nil && *subscription.NostrSecret != "" {
			decryptedSecret, err := decrypt(*subscription.NostrSecret)
			if err != nil {
				return nil, fmt.Errorf("failed to decrypt nostr secret: %w", err)
			}
			subscription.NostrSecret = &decryptedSecret
		}
	}

	return subscriptions, nil
}

func (r *SubscriptionRepository) Delete(id uuid.UUID) error {
	_, err := db.Exec("UPDATE subscriptions SET deleted_at=$1 WHERE id=$2", time.Now(), id)
	return err
}

func (s *SubscriptionService) Create(subscription *Subscription) (*Subscription, error) {
	now := time.Now()
	subscription.CreatedAt = now
	subscription.UpdatedAt = now

	// Set default values for new fields
	if subscription.Status == "" {
		subscription.Status = SubscriptionStatusActive
	}

	// If billing_interval_hours isn't set, try to get it from the product
	if subscription.BillingIntervalHours == nil {
		product, err := productService.Get(subscription.ProductID)
		if err == nil && product.BillingPeriodHours != nil {
			subscription.BillingIntervalHours = product.BillingPeriodHours
		}
	}

	// Set next_billing_date based on billing_start_date and interval
	if subscription.NextBillingDate.IsZero() {
		if subscription.BillingIntervalHours != nil {
			subscription.NextBillingDate = subscription.BillingStartDate.Add(
				time.Duration(*subscription.BillingIntervalHours) * time.Hour)
		} else {
			// Default to 30 days if no interval is available
			subscription.NextBillingDate = subscription.BillingStartDate.AddDate(0, 1, 0)
		}
	}

	createdSubscription, err := subscriptionRepository.Create(subscription)
	if err != nil {
		return nil, err
	}

	return createdSubscription, nil
}

func (s *SubscriptionService) Update(subscription *Subscription) error {
	subscription.UpdatedAt = time.Now()

	err := subscriptionRepository.Update(subscription)
	if err != nil {
		return err
	}

	return nil
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
	subscriptions, err := subscriptionRepository.GetByProduct(productID)
	if err != nil {
		return nil, err
	}

	return subscriptions, nil
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

	// Get current exchange rates
	rates := fiatRateService.GetRates()
	ratesJSON, err := json.Marshal(rates)
	if err != nil {
		return fmt.Errorf("failed to marshal rates: %w", err)
	}

	var amountSats int64
	if product.Currency != "btc" && product.Currency != "sats" {
		amountSats, err = fiatRateService.FiatToSatoshis(float64(product.Amount), product.Currency)
		if err != nil {
			return fmt.Errorf("failed to convert fiat to sats: %w", err)
		}
	} else {
		if product.Currency == "btc" {
			amountSats = int64(product.Amount * 100000000)
		} else {
			amountSats = int64(product.Amount)
		}
	}

	expirySeconds := int64(60 * 60)
	description := fmt.Sprintf("Subscription payment for %s", product.Name)
	invoice, err := walletService.MakeInvoice(sellerWallet.ID, amountSats*1000, description, expirySeconds)
	if err != nil {
		return fmt.Errorf("failed to create invoice: %w", err)
	}

	// Create default empty JSON for metadata and items
	emptyJSON := json.RawMessage([]byte("{}"))

	// Create checkout for this subscription payment
	checkout := &Checkout{
		ID:               uuid.New(),
		UserID:           subscription.UserID,
		AccountID:        subscription.AccountID,
		CustomerID:       &subscription.CustomerID,
		SubscriptionID:   &subscription.ID,
		ProductID:        &subscription.ProductID,
		Type:             CheckoutTypeSubscription, // Set proper type
		State:            CheckoutStateOpen,
		Amount:           amountSats, // Use the converted amount in sats, not product.Amount
		ReceivedAmount:   0,
		LightningInvoice: &invoice,
		Metadata:         &emptyJSON, // Initialize with empty JSON object
		Items:            &emptyJSON, // Initialize with empty JSON object
		Rates:            ratesJSON,  // Set current rates
		ExpiresAt:        time.Now().Add(time.Hour),
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}

	_, err = checkoutService.Create(checkout)
	if err != nil {
		return fmt.Errorf("failed to create checkout: %w", err)
	}

	// Pay the invoice
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

	// Poll for payment confirmation - similar to ConnectWallet method
	paymentSuccess := false
	var paymentErr error

	// Poll up to 20 times with 3 second intervals (60 seconds total)
	for i := 0; i < 20; i++ {
		time.Sleep(3 * time.Second)

		// Check if checkout state changed directly
		updatedCheckout, err := checkoutService.Get(checkout.ID)
		if err != nil {
			continue
		}

		// If checkout was already updated by webhook or other process
		if updatedCheckout.State == CheckoutStatePaid || updatedCheckout.State == CheckoutStateOverpaid {
			paymentSuccess = true
			break
		}

		// If not, check transactions directly
		if updatedCheckout.LightningInvoice != nil && *updatedCheckout.LightningInvoice != "" {
			responseData, err := walletService.ListTransactions(sellerWallet.ID, 0, 0, 50, 0, false, "incoming")
			if err != nil {
				logger.Error("Error listing transactions", "error", err)
				continue
			}

			var response TransactionResponse
			if err := json.Unmarshal(responseData, &response); err != nil {
				continue
			}

			if response.Error != nil {
				continue
			}

			// Look for our invoice in the transactions
			for _, tx := range response.Result.Transactions {
				if tx.Invoice == *updatedCheckout.LightningInvoice && tx.SettledAt != nil && tx.Preimage != "" {
					// Invoice has been paid, update the checkout state
					newState := CheckoutStatePaid
					receivedAmount := tx.Amount / 1000 // Convert from mSats to sats

					if receivedAmount < updatedCheckout.Amount {
						newState = CheckoutStateUnderpaid
					} else if receivedAmount > updatedCheckout.Amount {
						newState = CheckoutStateOverpaid
					}

					err = checkoutService.UpdateState(updatedCheckout.ID, newState, receivedAmount)
					if err == nil && (newState == CheckoutStatePaid || newState == CheckoutStateOverpaid) {
						paymentSuccess = true
					} else if err != nil {
						paymentErr = fmt.Errorf("failed to update checkout state: %w", err)
					}
					break // Exit the transaction loop as we've found our invoice
				}
			}

			if paymentSuccess || paymentErr != nil {
				break // Exit the polling loop
			}
		}
	}

	// If we complete polling without confirming payment
	if !paymentSuccess && paymentErr == nil {
		paymentErr = fmt.Errorf("payment confirmation timed out")
	}

	if paymentErr != nil {
		return paymentErr
	}

	return nil
}

func (s *SubscriptionService) ProcessSubscriptionRenewals() {
	logger.Info("Starting subscription renewal processing")

	// Get subscriptions due for billing up to now
	now := time.Now()
	dueSubscriptions, err := subscriptionRepository.GetSubscriptionsDueForBilling(now)
	if err != nil {
		logger.Error("Failed to get subscriptions due for billing", "error", err)
		return
	}

	logger.Info("Processing subscription renewals", "count", len(dueSubscriptions))

	// Process each subscription in its own goroutine
	for _, subscription := range dueSubscriptions {
		go s.ProcessRenewal(subscription)
	}
}

func (s *SubscriptionService) ProcessRenewal(subscription *Subscription) {
	logger.Info("Processing subscription renewal",
		"subscription_id", subscription.ID,
		"customer_id", subscription.CustomerID)

	// Process payment using existing method
	err := s.ProcessSubscriptionPayment(subscription)

	now := time.Now()

	if err != nil {
		logger.Error("Subscription payment failed",
			"subscription_id", subscription.ID,
			"customer_id", subscription.CustomerID,
			"error", err)

		// Update subscription with failed payment details
		failedStatus := PaymentStatusFailed
		subscription.LastPaymentStatus = &failedStatus
		subscription.LastPaymentDate = &now
		subscription.FailedPaymentAttempts++

		// Calculate next retry time based on billing interval
		var retryWaitDuration time.Duration

		if subscription.BillingIntervalHours != nil && *subscription.BillingIntervalHours > 0 {
			// Calculate minutes to wait based on percentage of billing interval
			billingIntervalMinutes := float64(*subscription.BillingIntervalHours) * 60

			// Apply exponential backoff based on failed attempts (2^n - 1)
			failureFactor := math.Pow(2, float64(subscription.FailedPaymentAttempts)) - 1

			// Calculate adaptive retry time (in minutes)
			retryWaitMinutes := math.Min(
				billingIntervalMinutes*MaxRetryWaitPercentage*failureFactor,
				billingIntervalMinutes*0.8, // Never wait more than 80% of billing interval
			)

			// Ensure minimum wait time
			retryWaitMinutes = math.Max(retryWaitMinutes, float64(MinRetryWaitMinutes))

			retryWaitDuration = time.Duration(retryWaitMinutes) * time.Minute

			logger.Info("Calculated adaptive retry wait time",
				"subscription_id", subscription.ID,
				"billing_interval_hours", *subscription.BillingIntervalHours,
				"failed_attempts", subscription.FailedPaymentAttempts,
				"retry_wait_minutes", retryWaitMinutes)
		} else {
			// Fallback to default retry interval if billing interval is unknown
			retryWaitDuration = time.Duration(DefaultRetryIntervalHours) * time.Hour
		}

		// Set the next billing date to now + retry wait time
		subscription.NextBillingDate = now.Add(retryWaitDuration)

		// Suspend subscription after too many failures
		if subscription.FailedPaymentAttempts >= MaxPaymentRetryAttempts {
			subscription.Status = SubscriptionStatusSuspended

			// Send notification about suspension
			notificationData := map[string]interface{}{
				"subscription_id": subscription.ID.String(),
				"customer_id":     subscription.CustomerID.String(),
				"max_attempts":    MaxPaymentRetryAttempts,
			}
			notificationService.SendNotification(
				NotificationEventSubscriptionSuspended,
				subscription.AccountID,
				notificationData,
			)

			// Send webhook about suspension
			webhookService.DeliverWebhook(
				WebhookEventSubscriptionSuspended,
				subscription.AccountID,
				subscription,
			)
		} else {
			// Send notification about failed payment
			notificationData := map[string]interface{}{
				"subscription_id": subscription.ID.String(),
				"customer_id":     subscription.CustomerID.String(),
				"attempt":         subscription.FailedPaymentAttempts,
				"max_attempts":    MaxPaymentRetryAttempts,
				"next_retry_date": subscription.NextBillingDate,
			}
			notificationService.SendNotification(
				NotificationEventSubscriptionPaymentFailed,
				subscription.AccountID,
				notificationData,
			)

			// Send webhook about failed payment
			webhookService.DeliverWebhook(
				WebhookEventSubscriptionPaymentFailed,
				subscription.AccountID,
				subscription,
			)
		}
	} else {
		// Payment was successful
		successStatus := PaymentStatusSuccess
		subscription.LastPaymentStatus = &successStatus
		subscription.LastPaymentDate = &now
		subscription.FailedPaymentAttempts = 0

		// If subscription was suspended and payment succeeded, reactivate it
		if subscription.Status == SubscriptionStatusSuspended {
			subscription.Status = SubscriptionStatusActive

			// Send notification about reactivation
			notificationData := map[string]interface{}{
				"subscription_id": subscription.ID.String(),
				"customer_id":     subscription.CustomerID.String(),
			}
			notificationService.SendNotification(
				NotificationEventSubscriptionReactivated,
				subscription.AccountID,
				notificationData,
			)

			// Send webhook about reactivation
			webhookService.DeliverWebhook(
				WebhookEventSubscriptionReactivated,
				subscription.AccountID,
				subscription,
			)
		}

		// Calculate next billing date based on billing interval
		if subscription.BillingIntervalHours != nil {
			subscription.NextBillingDate = now.Add(
				time.Duration(*subscription.BillingIntervalHours) * time.Hour)
		} else {
			// Default to 30 days if no interval is available
			subscription.NextBillingDate = now.AddDate(0, 1, 0)
		}

		// Send notification about successful payment
		notificationData := map[string]interface{}{
			"subscription_id":   subscription.ID.String(),
			"customer_id":       subscription.CustomerID.String(),
			"next_billing_date": subscription.NextBillingDate,
		}
		notificationService.SendNotification(
			NotificationEventSubscriptionPaymentSuccessful,
			subscription.AccountID,
			notificationData,
		)

		// Send webhook about successful payment
		webhookService.DeliverWebhook(
			WebhookEventSubscriptionPaymentSuccessful,
			subscription.AccountID,
			subscription,
		)
	}

	// Update the subscription in the database
	subscription.UpdatedAt = now
	if err := subscriptionRepository.Update(subscription); err != nil {
		logger.Error("Failed to update subscription after renewal processing",
			"subscription_id", subscription.ID, "error", err)
	}
}

func (r *SubscriptionRepository) GetSubscriptionsDueForBilling(cutoffTime time.Time) ([]*Subscription, error) {
	subscriptions := []*Subscription{}
	err := db.Select(&subscriptions, `
		SELECT * FROM subscriptions 
		WHERE status = $1 
		AND next_billing_date <= $2 
		AND deleted_at IS NULL 
		ORDER BY next_billing_date ASC`,
		SubscriptionStatusActive, cutoffTime)
	if err != nil {
		return nil, err
	}

	// Decrypt the nostr secret for each subscription
	for _, subscription := range subscriptions {
		if subscription.NostrSecret != nil && *subscription.NostrSecret != "" {
			decryptedSecret, err := decrypt(*subscription.NostrSecret)
			if err != nil {
				return nil, fmt.Errorf("failed to decrypt nostr secret: %w", err)
			}
			subscription.NostrSecret = &decryptedSecret
		}
	}

	return subscriptions, nil
}

func processSubscriptionRenewals() {
	subscriptionService.ProcessSubscriptionRenewals()
}

func InitSubscriptionScheduler() {
	logger.Info("Initializing subscription scheduler")

	// Process immediately on startup
	go processSubscriptionRenewals()

	// Then schedule regular processing
	go func() {
		// Check every 10 minutes by default
		interval := 1 * time.Minute

		// Allow configuration via environment variable
		if envInterval := os.Getenv("SUBSCRIPTION_CHECK_INTERVAL"); envInterval != "" {
			if parsed, err := time.ParseDuration(envInterval); err == nil {
				interval = parsed
			}
		}

		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				processSubscriptionRenewals()
			}
		}
	}()
}

type SubscriptionHandler struct {
	Validator *validator.Validate
}

var subscriptionHandler = &SubscriptionHandler{
	Validator: validator.New(),
}

func (h *SubscriptionHandler) Create(w http.ResponseWriter, r *http.Request) {
	var input struct {
		AccountID        uuid.UUID       `json:"account_id"`
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

	var account *Account
	_, apiKeyErr := GetAPIKeyFromContext(r.Context())

	if apiKeyErr == nil {
		if !CheckAPIPermission(r.Context(), "subscriptions", "create") {
			JsonResponse(w, http.StatusForbidden, "API key doesn't have permission to create subscriptions", nil)
			return
		}

		account, err = GetAccountFromContext(r.Context())
		if err != nil {
			JsonResponse(w, http.StatusInternalServerError, "Error retrieving account", err.Error())
			return
		}

		input.AccountID = account.ID
	} else {
		if input.AccountID == uuid.Nil {
			JsonResponse(w, http.StatusBadRequest, "Account ID is required", nil)
			return
		}

		account, err = accountService.Get(input.AccountID)
		if err != nil {
			JsonResponse(w, http.StatusBadRequest, "Invalid account ID", err.Error())
			return
		}

		if account.UserID != user.ID {
			JsonResponse(w, http.StatusForbidden, "You are not authorized to create subscriptions for this account", nil)
			return
		}
	}

	customer, err := customerService.Get(input.CustomerID)
	if err != nil {
		JsonResponse(w, http.StatusNotFound, "Customer not found", err.Error())
		return
	}

	if customer.AccountID != input.AccountID {
		JsonResponse(w, http.StatusBadRequest, "Customer does not belong to this account", nil)
		return
	}

	product, err := productService.Get(input.ProductID)
	if err != nil {
		JsonResponse(w, http.StatusNotFound, "Product not found", err.Error())
		return
	}

	if product.AccountID != input.AccountID {
		JsonResponse(w, http.StatusBadRequest, "Product does not belong to this account", nil)
		return
	}

	if !product.IsRecurring {
		JsonResponse(w, http.StatusBadRequest, "Cannot create subscription for non-recurring product", nil)
		return
	}

	billingStartDate := time.Now()
	if input.BillingStartDate != nil {
		billingStartDate = *input.BillingStartDate
	}

	activeOnDate := time.Now()
	if input.ActiveOnDate != nil {
		activeOnDate = *input.ActiveOnDate
	}

	metadata := input.Metadata
	if len(metadata) == 0 {
		metadata = json.RawMessage(`{}`)
	}

	subscription := &Subscription{
		ID:               uuid.New(),
		UserID:           user.ID,
		AccountID:        input.AccountID,
		CustomerID:       input.CustomerID,
		ProductID:        input.ProductID,
		BillingStartDate: billingStartDate,
		ActiveOnDate:     activeOnDate,
		Metadata:         metadata,
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
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		JsonResponse(w, http.StatusBadRequest, "Invalid subscription ID", nil)
		return
	}

	existingSubscription, err := subscriptionService.Get(id)
	if err != nil {
		JsonResponse(w, http.StatusNotFound, "Subscription not found", err.Error())
		return
	}

	user, err := GetUserFromContext(r.Context())
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error retrieving user", err.Error())
		return
	}

	_, apiKeyErr := GetAPIKeyFromContext(r.Context())
	if apiKeyErr == nil {
		if !CheckAPIPermission(r.Context(), "subscriptions", "update") {
			JsonResponse(w, http.StatusForbidden, "API key doesn't have permission to update subscriptions", nil)
			return
		}

		account, err := GetAccountFromContext(r.Context())
		if err != nil {
			JsonResponse(w, http.StatusInternalServerError, "Error retrieving account", err.Error())
			return
		}

		if existingSubscription.AccountID != account.ID {
			JsonResponse(w, http.StatusForbidden, "This subscription belongs to a different account", nil)
			return
		}
	} else {
		if existingSubscription.UserID != user.ID {
			JsonResponse(w, http.StatusForbidden, "You are not authorized to update this subscription", nil)
			return
		}
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

	if len(input.Metadata) > 0 {
		existingSubscription.Metadata = input.Metadata
	}

	if input.NostrRelay != nil {
		existingSubscription.NostrRelay = input.NostrRelay
	}

	if input.NostrPubkey != nil {
		existingSubscription.NostrPubkey = input.NostrPubkey
	}

	if input.NostrSecret != nil {
		existingSubscription.NostrSecret = input.NostrSecret
	}

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

	_, apiKeyErr := GetAPIKeyFromContext(r.Context())
	if apiKeyErr == nil {
		if !CheckAPIPermission(r.Context(), "subscriptions", "read") {
			JsonResponse(w, http.StatusForbidden, "API key doesn't have permission to read subscriptions", nil)
			return
		}

		account, err := GetAccountFromContext(r.Context())
		if err != nil {
			JsonResponse(w, http.StatusInternalServerError, "Error retrieving account", err.Error())
			return
		}

		if subscription.AccountID != account.ID {
			JsonResponse(w, http.StatusForbidden, "This subscription belongs to a different account", nil)
			return
		}
	} else {
		if subscription.UserID != user.ID {
			JsonResponse(w, http.StatusForbidden, "You are not authorized to view this subscription", nil)
			return
		}
	}

	JsonResponse(w, http.StatusOK, "Subscription retrieved successfully", subscription)
}

func (h *SubscriptionHandler) GetAll(w http.ResponseWriter, r *http.Request) {
	user, err := GetUserFromContext(r.Context())
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error retrieving user", err.Error())
		return
	}

	_, apiKeyErr := GetAPIKeyFromContext(r.Context())
	if apiKeyErr == nil {
		if !CheckAPIPermission(r.Context(), "subscriptions", "read") {
			JsonResponse(w, http.StatusForbidden, "API key doesn't have permission to read subscriptions", nil)
			return
		}

		account, err := GetAccountFromContext(r.Context())
		if err != nil {
			JsonResponse(w, http.StatusInternalServerError, "Error retrieving account", err.Error())
			return
		}

		subscriptions, err := subscriptionService.GetByAccount(account.ID)
		if err != nil {
			JsonResponse(w, http.StatusInternalServerError, "Error retrieving subscriptions", err.Error())
			return
		}

		JsonResponse(w, http.StatusOK, "Subscriptions retrieved successfully", subscriptions)
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

	_, apiKeyErr := GetAPIKeyFromContext(r.Context())
	if apiKeyErr == nil {
		if !CheckAPIPermission(r.Context(), "subscriptions", "read") {
			JsonResponse(w, http.StatusForbidden, "API key doesn't have permission to read subscriptions", nil)
			return
		}

		account, err := GetAccountFromContext(r.Context())
		if err != nil {
			JsonResponse(w, http.StatusInternalServerError, "Error retrieving account", err.Error())
			return
		}

		if accountID != account.ID {
			JsonResponse(w, http.StatusForbidden, "This account ID doesn't match the API key's account", nil)
			return
		}
	} else {
		account, err := accountService.Get(accountID)
		if err != nil {
			JsonResponse(w, http.StatusNotFound, "Account not found", err.Error())
			return
		}

		if account.UserID != user.ID {
			JsonResponse(w, http.StatusForbidden, "You are not authorized to view subscriptions for this account", nil)
			return
		}
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

	_, apiKeyErr := GetAPIKeyFromContext(r.Context())
	if apiKeyErr == nil {
		if !CheckAPIPermission(r.Context(), "subscriptions", "read") {
			JsonResponse(w, http.StatusForbidden, "API key doesn't have permission to read subscriptions", nil)
			return
		}

		account, err := GetAccountFromContext(r.Context())
		if err != nil {
			JsonResponse(w, http.StatusInternalServerError, "Error retrieving account", err.Error())
			return
		}

		if customer.AccountID != account.ID {
			JsonResponse(w, http.StatusForbidden, "This customer belongs to a different account", nil)
			return
		}
	} else {
		if customer.UserID != user.ID {
			JsonResponse(w, http.StatusForbidden, "You are not authorized to view subscriptions for this customer", nil)
			return
		}
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

	_, apiKeyErr := GetAPIKeyFromContext(r.Context())
	if apiKeyErr == nil {
		if !CheckAPIPermission(r.Context(), "subscriptions", "read") {
			JsonResponse(w, http.StatusForbidden, "API key doesn't have permission to read subscriptions", nil)
			return
		}

		account, err := GetAccountFromContext(r.Context())
		if err != nil {
			JsonResponse(w, http.StatusInternalServerError, "Error retrieving account", err.Error())
			return
		}

		if product.AccountID != account.ID {
			JsonResponse(w, http.StatusForbidden, "This product belongs to a different account", nil)
			return
		}
	} else {
		if product.UserID != user.ID {
			JsonResponse(w, http.StatusForbidden, "You are not authorized to view subscriptions for this product", nil)
			return
		}
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

	_, apiKeyErr := GetAPIKeyFromContext(r.Context())
	if apiKeyErr == nil {
		if !CheckAPIPermission(r.Context(), "subscriptions", "delete") {
			JsonResponse(w, http.StatusForbidden, "API key doesn't have permission to delete subscriptions", nil)
			return
		}

		account, err := GetAccountFromContext(r.Context())
		if err != nil {
			JsonResponse(w, http.StatusInternalServerError, "Error retrieving account", err.Error())
			return
		}

		if subscription.AccountID != account.ID {
			JsonResponse(w, http.StatusForbidden, "This subscription belongs to a different account", nil)
			return
		}
	} else {
		if subscription.UserID != user.ID {
			JsonResponse(w, http.StatusForbidden, "You are not authorized to delete this subscription", nil)
			return
		}
	}

	err = subscriptionService.Delete(id)
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error deleting subscription", err.Error())
		return
	}

	JsonResponse(w, http.StatusOK, "Subscription deleted successfully", nil)
}
