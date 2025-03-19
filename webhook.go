package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"

	"database/sql/driver"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
)

type WebhookEvent string

const (
	WebhookEventCheckoutCreated   WebhookEvent = "checkout.created"
	WebhookEventCheckoutPaid      WebhookEvent = "checkout.paid"
	WebhookEventCheckoutUnderpaid WebhookEvent = "checkout.underpaid"
	WebhookEventCheckoutOverpaid  WebhookEvent = "checkout.overpaid"
	WebhookEventCheckoutExpired   WebhookEvent = "checkout.expired"
)

var AllWebhookEvents = []WebhookEvent{
	WebhookEventCheckoutCreated,
	WebhookEventCheckoutPaid,
	WebhookEventCheckoutUnderpaid,
	WebhookEventCheckoutOverpaid,
	WebhookEventCheckoutExpired,
}

// Custom type to handle JSONB for WebhookEvent
type WebhookEventList []WebhookEvent

// Implement the Valuer interface for the custom type
func (we WebhookEventList) Value() (driver.Value, error) {
	return json.Marshal(we)
}

// Implement the Scanner interface for the custom type
func (we *WebhookEventList) Scan(value interface{}) error {
	if value == nil {
		*we = []WebhookEvent{}
		return nil
	}

	bytes, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("failed to scan WebhookEventList: %v", value)
	}

	return json.Unmarshal(bytes, we)
}

type Webhook struct {
	ID          uuid.UUID        `db:"id" json:"id"`
	UserID      uuid.UUID        `db:"user_id" json:"user_id"`
	AccountID   uuid.UUID        `db:"account_id" json:"account_id"`
	URL         string           `db:"url" json:"url" validate:"required,url"`
	Description string           `db:"description" json:"description"`
	Secret      string           `db:"secret" json:"secret,omitempty"`
	Enabled     bool             `db:"enabled" json:"enabled"`
	Events      WebhookEventList `db:"events" json:"events" validate:"required"`
	CreatedAt   time.Time        `db:"created_at" json:"created_at"`
	UpdatedAt   time.Time        `db:"updated_at" json:"updated_at"`
	DeletedAt   *time.Time       `db:"deleted_at" json:"deleted_at,omitempty"`
}

type WebhookWithoutSecret struct {
	ID          uuid.UUID      `json:"id"`
	UserID      uuid.UUID      `json:"user_id"`
	AccountID   uuid.UUID      `json:"account_id"`
	URL         string         `json:"url"`
	Description string         `json:"description"`
	Enabled     bool           `json:"enabled"`
	Events      []WebhookEvent `json:"events"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
}

type WebhookPayload struct {
	ID        string          `json:"id"`
	Event     WebhookEvent    `json:"event"`
	CreatedAt time.Time       `json:"created_at"`
	Data      json.RawMessage `json:"data"`
}

type WebhookCache struct {
	cache sync.Map
}

func (c *WebhookCache) GetByAccount(accountID uuid.UUID) ([]*Webhook, bool) {
	value, ok := c.cache.Load(accountID)
	if !ok {
		return nil, false
	}
	webhooks, ok := value.([]*Webhook)
	return webhooks, ok
}

func (c *WebhookCache) SetForAccount(accountID uuid.UUID, webhooks []*Webhook) {
	c.cache.Store(accountID, webhooks)
}

func (c *WebhookCache) InvalidateForAccount(accountID uuid.UUID) {
	c.cache.Delete(accountID)
}

type WebhookDeliveryStatus string

const (
	WebhookDeliveryStatusPending    WebhookDeliveryStatus = "pending"
	WebhookDeliveryStatusSuccessful WebhookDeliveryStatus = "successful"
	WebhookDeliveryStatusFailed     WebhookDeliveryStatus = "failed"
)

// WebhookDelivery represents a webhook delivery attempt
type WebhookDelivery struct {
	ID                 uuid.UUID             `db:"id" json:"id"`
	WebhookID          uuid.UUID             `db:"webhook_id" json:"webhook_id"`
	EventType          WebhookEvent          `db:"event_type" json:"event_type"`
	Status             WebhookDeliveryStatus `db:"status" json:"status"`
	RequestPayload     json.RawMessage       `db:"request_payload" json:"request_payload"`
	ResponseBody       string                `db:"response_body" json:"response_body"`
	ResponseStatusCode int                   `db:"response_status_code" json:"response_status_code"`
	DurationMs         int                   `db:"duration_ms" json:"duration_ms"`
	ErrorMessage       string                `db:"error_message" json:"error_message"`
	CreatedAt          time.Time             `db:"created_at" json:"created_at"`
	UpdatedAt          time.Time             `db:"updated_at" json:"updated_at"`
}

type WebhookRepository struct{}

func (r *WebhookRepository) Create(webhook *Webhook) (*Webhook, error) {
	webhook.ID = uuid.New()
	eventsJSON, err := json.Marshal(webhook.Events)
	if err != nil {
		return nil, err
	}

	err = db.QueryRowx(`
		INSERT INTO webhooks (
			id, user_id, account_id, url, description, secret, 
			enabled, events, created_at, updated_at, deleted_at
		) VALUES (
			$1, $2, $3, $4, $5, 
			$6, $7, $8, $9, $10, $11
		) RETURNING id`,
		webhook.ID, webhook.UserID, webhook.AccountID, webhook.URL, webhook.Description, webhook.Secret,
		webhook.Enabled, eventsJSON, webhook.CreatedAt, webhook.UpdatedAt, webhook.DeletedAt,
	).Scan(&webhook.ID)

	return webhook, err
}

func (r *WebhookRepository) Get(id uuid.UUID) (*Webhook, error) {
	webhook := &Webhook{}
	err := db.Get(webhook, `
		SELECT id, user_id, account_id, url, description, secret, 
			enabled, events, created_at, updated_at, deleted_at
		FROM webhooks
		WHERE id = $1 AND deleted_at IS NULL`,
		id,
	)
	return webhook, err
}

func (r *WebhookRepository) GetByUser(userID uuid.UUID) ([]*Webhook, error) {
	webhooks := []*Webhook{}
	err := db.Select(&webhooks, `
		SELECT id, user_id, account_id, url, description, secret, 
			enabled, events, created_at, updated_at, deleted_at
		FROM webhooks
		WHERE user_id = $1 AND deleted_at IS NULL
		ORDER BY created_at DESC`,
		userID,
	)
	return webhooks, err
}

func (r *WebhookRepository) GetByAccount(accountID uuid.UUID) ([]*Webhook, error) {
	webhooks := []*Webhook{}
	err := db.Select(&webhooks, `
		SELECT id, user_id, account_id, url, description, secret, 
			enabled, events, created_at, updated_at, deleted_at
		FROM webhooks
		WHERE account_id = $1 AND deleted_at IS NULL
		ORDER BY created_at DESC`,
		accountID,
	)
	return webhooks, err
}

func (r *WebhookRepository) GetByAccountAndEvent(accountID uuid.UUID, event WebhookEvent) ([]*Webhook, error) {
	webhooks := []*Webhook{}
	err := db.Select(&webhooks, `
		SELECT id, user_id, account_id, url, description, secret, 
			enabled, events, created_at, updated_at, deleted_at
		FROM webhooks
		WHERE account_id = $1 AND deleted_at IS NULL AND enabled = true
			AND events::jsonb ? $2
		ORDER BY created_at DESC`,
		accountID, event,
	)
	return webhooks, err
}

func (r *WebhookRepository) Update(webhook *Webhook) error {
	_, err := db.Exec(`
		UPDATE webhooks SET 
			url = $1, 
			description = $2,
			enabled = $3,
			events = $4,
			updated_at = $5,
			deleted_at = $6
		WHERE id = $7`,
		webhook.URL, webhook.Description, webhook.Enabled, webhook.Events,
		webhook.UpdatedAt, webhook.DeletedAt, webhook.ID,
	)
	return err
}

func (r *WebhookRepository) UpdateSecret(id uuid.UUID, secret string) error {
	_, err := db.Exec(`
		UPDATE webhooks SET 
			secret = $1,
			updated_at = $2
		WHERE id = $3`,
		secret, time.Now(), id,
	)
	return err
}

func (r *WebhookRepository) Delete(id uuid.UUID) error {
	now := time.Now()
	_, err := db.Exec(`
		UPDATE webhooks SET 
			deleted_at = $1
		WHERE id = $2`,
		now, id,
	)
	return err
}

func (r *WebhookRepository) CreateDelivery(delivery *WebhookDelivery) error {
	_, err := db.Exec(`
		INSERT INTO webhook_deliveries (
			id, webhook_id, event_type, status, request_payload, 
			response_body, response_status_code, duration_ms, error_message,
			created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11
		)`,
		delivery.ID, delivery.WebhookID, delivery.EventType, delivery.Status,
		delivery.RequestPayload, delivery.ResponseBody, delivery.ResponseStatusCode,
		delivery.DurationMs, delivery.ErrorMessage, delivery.CreatedAt, delivery.UpdatedAt,
	)
	return err
}

func (r *WebhookRepository) GetDelivery(id uuid.UUID) (*WebhookDelivery, error) {
	delivery := &WebhookDelivery{}
	err := db.Get(delivery, `
		SELECT id, webhook_id, event_type, status, request_payload, 
			response_body, response_status_code, duration_ms, error_message,
			created_at, updated_at
		FROM webhook_deliveries
		WHERE id = $1`,
		id,
	)
	return delivery, err
}

func (r *WebhookRepository) GetDeliveriesByWebhook(webhookID uuid.UUID, limit, offset int) ([]*WebhookDelivery, error) {
	deliveries := []*WebhookDelivery{}
	err := db.Select(&deliveries, `
		SELECT id, webhook_id, event_type, status, request_payload, 
			response_body, response_status_code, duration_ms, error_message,
			created_at, updated_at
		FROM webhook_deliveries
		WHERE webhook_id = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3`,
		webhookID, limit, offset,
	)
	return deliveries, err
}

func (r *WebhookRepository) UpdateDelivery(delivery *WebhookDelivery) error {
	_, err := db.Exec(`
		UPDATE webhook_deliveries SET 
			status = $1,
			response_body = $2,
			response_status_code = $3,
			duration_ms = $4,
			error_message = $5,
			updated_at = $6
		WHERE id = $7`,
		delivery.Status, delivery.ResponseBody, delivery.ResponseStatusCode,
		delivery.DurationMs, delivery.ErrorMessage, delivery.UpdatedAt, delivery.ID,
	)
	return err
}

type WebhookService struct {
	httpClient *http.Client
}

var webhookRepository = &WebhookRepository{}
var webhookCache = &WebhookCache{}
var webhookService *WebhookService

func NewWebhookService() *WebhookService {
	return &WebhookService{
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// GenerateRandomString generates a random string of the specified length
func GenerateRandomString(length int) (string, error) {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func (s *WebhookService) Create(webhook *Webhook) (*Webhook, error) {
	webhook.CreatedAt = time.Now()
	webhook.UpdatedAt = time.Now()

	randomString, err := GenerateRandomString(32)
	if err != nil {
		return nil, err
	}

	hash := sha256.New()
	hash.Write([]byte(randomString))
	webhook.Secret = hex.EncodeToString(hash.Sum(nil))

	createdWebhook, err := webhookRepository.Create(webhook)
	if err != nil {
		return nil, err
	}

	webhookCache.InvalidateForAccount(webhook.AccountID)

	return createdWebhook, nil
}

func (s *WebhookService) Get(id uuid.UUID) (*Webhook, error) {
	return webhookRepository.Get(id)
}

func (s *WebhookService) GetByUser(userID uuid.UUID) ([]*Webhook, error) {
	return webhookRepository.GetByUser(userID)
}

func (s *WebhookService) GetByAccount(accountID uuid.UUID) ([]*Webhook, error) {
	if cachedWebhooks, found := webhookCache.GetByAccount(accountID); found {
		return cachedWebhooks, nil
	}

	webhooks, err := webhookRepository.GetByAccount(accountID)
	if err != nil {
		return nil, err
	}

	webhookCache.SetForAccount(accountID, webhooks)
	return webhooks, nil
}

func (s *WebhookService) GetByAccountAndEvent(accountID uuid.UUID, event WebhookEvent) ([]*Webhook, error) {
	return webhookRepository.GetByAccountAndEvent(accountID, event)
}

func (s *WebhookService) Update(webhook *Webhook) error {
	webhook.UpdatedAt = time.Now()

	err := webhookRepository.Update(webhook)
	if err != nil {
		return err
	}

	webhookCache.InvalidateForAccount(webhook.AccountID)

	return nil
}

func (s *WebhookService) RegenerateSecret(id uuid.UUID) (string, error) {
	webhook, err := webhookRepository.Get(id)
	if err != nil {
		return "", err
	}

	newSecret, err := GenerateRandomString(32)
	if err != nil {
		return "", err
	}

	err = webhookRepository.UpdateSecret(id, newSecret)
	if err != nil {
		return "", err
	}

	webhookCache.InvalidateForAccount(webhook.AccountID)

	return newSecret, nil
}

func (s *WebhookService) Delete(id uuid.UUID) error {
	webhook, err := webhookRepository.Get(id)
	if err != nil {
		return err
	}

	err = webhookRepository.Delete(id)
	if err != nil {
		return err
	}

	webhookCache.InvalidateForAccount(webhook.AccountID)

	return nil
}

func (s *WebhookService) GenerateSignature(payload []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

func (s *WebhookService) DeliverWebhook(event WebhookEvent, accountID uuid.UUID, data interface{}) {
	webhooks, err := s.GetByAccountAndEvent(accountID, event)
	if err != nil || len(webhooks) == 0 {
		return
	}

	dataBytes, err := json.Marshal(data)
	if err != nil {
		fmt.Printf("Error marshaling webhook data: %v\n", err)
		return
	}

	payload := WebhookPayload{
		ID:        uuid.New().String(),
		Event:     event,
		CreatedAt: time.Now(),
		Data:      json.RawMessage(dataBytes),
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		fmt.Printf("Error marshaling webhook payload: %v\n", err)
		return
	}

	for _, webhook := range webhooks {
		go func(wh *Webhook) {
			s.deliverSingleWebhook(wh, event, payloadBytes)
		}(webhook)
	}
}

func (s *WebhookService) deliverSingleWebhook(webhook *Webhook, event WebhookEvent, payloadBytes []byte) {
	deliveryID := uuid.New()
	startTime := time.Now()

	// Create initial delivery record with pending status
	delivery := &WebhookDelivery{
		ID:             deliveryID,
		WebhookID:      webhook.ID,
		EventType:      event,
		Status:         WebhookDeliveryStatusPending,
		RequestPayload: payloadBytes,
		CreatedAt:      startTime,
		UpdatedAt:      startTime,
	}

	err := webhookRepository.CreateDelivery(delivery)
	if err != nil {
		fmt.Printf("Error creating webhook delivery record: %v\n", err)
		// Continue with delivery attempt even if logging fails
	}

	signature := s.GenerateSignature(payloadBytes, webhook.Secret)

	req, err := http.NewRequest("POST", webhook.URL, bytes.NewBuffer(payloadBytes))
	if err != nil {
		endTime := time.Now()
		duration := int(endTime.Sub(startTime).Milliseconds())

		delivery.Status = WebhookDeliveryStatusFailed
		delivery.ErrorMessage = fmt.Sprintf("Error creating request: %v", err)
		delivery.DurationMs = duration
		delivery.UpdatedAt = endTime

		_ = webhookRepository.UpdateDelivery(delivery)
		fmt.Printf("Error creating webhook request: %v\n", err)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Signature", signature)
	req.Header.Set("X-Webhook-ID", fmt.Sprintf("%s", webhook.ID))
	req.Header.Set("X-Event", string(event))

	resp, err := s.httpClient.Do(req)
	endTime := time.Now()
	duration := int(endTime.Sub(startTime).Milliseconds())

	delivery.DurationMs = duration
	delivery.UpdatedAt = endTime

	if err != nil {
		delivery.Status = WebhookDeliveryStatusFailed
		delivery.ErrorMessage = fmt.Sprintf("Error sending request: %v", err)

		_ = webhookRepository.UpdateDelivery(delivery)
		fmt.Printf("Error delivering webhook: %v\n", err)
		return
	}

	// Read response body
	respBody, err := io.ReadAll(resp.Body)
	resp.Body.Close()

	delivery.ResponseStatusCode = resp.StatusCode
	delivery.ResponseBody = string(respBody)

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		delivery.Status = WebhookDeliveryStatusSuccessful
	} else {
		delivery.Status = WebhookDeliveryStatusFailed
		delivery.ErrorMessage = fmt.Sprintf("Webhook delivery failed with status code: %d", resp.StatusCode)
		fmt.Printf("Webhook delivery error: status code %d\n", resp.StatusCode)
	}

	_ = webhookRepository.UpdateDelivery(delivery)
}

func (s *WebhookService) RetryDelivery(deliveryID uuid.UUID) (*WebhookDelivery, error) {
	delivery, err := webhookRepository.GetDelivery(deliveryID)
	if err != nil {
		return nil, err
	}

	webhook, err := webhookRepository.Get(delivery.WebhookID)
	if err != nil {
		return nil, err
	}

	// Create a new delivery record based on the failed one
	newDelivery := &WebhookDelivery{
		ID:             uuid.New(),
		WebhookID:      webhook.ID,
		EventType:      delivery.EventType,
		Status:         WebhookDeliveryStatusPending,
		RequestPayload: delivery.RequestPayload,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}

	err = webhookRepository.CreateDelivery(newDelivery)
	if err != nil {
		return nil, err
	}

	// Deliver the webhook in the background
	go func() {
		s.deliverSingleWebhook(webhook, delivery.EventType, delivery.RequestPayload)
	}()

	return newDelivery, nil
}

func (s *WebhookService) GetDelivery(id uuid.UUID) (*WebhookDelivery, error) {
	return webhookRepository.GetDelivery(id)
}

func (s *WebhookService) GetDeliveriesByWebhook(webhookID uuid.UUID, limit, offset int) ([]*WebhookDelivery, error) {
	return webhookRepository.GetDeliveriesByWebhook(webhookID, limit, offset)
}

type WebhookHandler struct {
	Validator *validator.Validate
}

var webhookHandler = &WebhookHandler{
	Validator: validator.New(),
}

func (h *WebhookHandler) Create(w http.ResponseWriter, r *http.Request) {
	var input struct {
		AccountID   uuid.UUID        `json:"account_id"`
		URL         string           `json:"url" validate:"required,url"`
		Description string           `json:"description"`
		Events      WebhookEventList `json:"events" validate:"required"`
		Enabled     bool             `json:"enabled"`
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
		if !CheckAPIPermission(r.Context(), "webhooks", "create") {
			JsonResponse(w, http.StatusForbidden, "API key doesn't have permission to create webhooks", nil)
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
			JsonResponse(w, http.StatusForbidden, "You are not authorized to create webhooks for this account", nil)
			return
		}
	}

	// Generate a webhook secret
	secret := make([]byte, 32)
	_, err = rand.Read(secret)
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error generating webhook secret", err.Error())
		return
	}
	secretHex := hex.EncodeToString(secret)

	webhook := &Webhook{
		UserID:      user.ID,
		AccountID:   input.AccountID,
		URL:         input.URL,
		Description: input.Description,
		Secret:      secretHex,
		Enabled:     input.Enabled,
		Events:      input.Events,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	createdWebhook, err := webhookService.Create(webhook)
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error creating webhook", err.Error())
		return
	}

	response := map[string]interface{}{
		"webhook": createdWebhook,
		"secret":  secretHex,
	}

	JsonResponse(w, http.StatusCreated, "Webhook created successfully", response)
}

func (h *WebhookHandler) Get(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	if idStr == "" {
		JsonResponse(w, http.StatusBadRequest, "Webhook ID is required", nil)
		return
	}

	id, err := uuid.Parse(idStr)
	if err != nil {
		JsonResponse(w, http.StatusBadRequest, "Invalid webhook ID", err.Error())
		return
	}

	webhook, err := webhookService.Get(id)
	if err != nil {
		JsonResponse(w, http.StatusNotFound, "Webhook not found", err.Error())
		return
	}

	user, err := GetUserFromContext(r.Context())
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error retrieving user", err.Error())
		return
	}

	_, apiKeyErr := GetAPIKeyFromContext(r.Context())
	if apiKeyErr == nil {
		if !CheckAPIPermission(r.Context(), "webhooks", "read") {
			JsonResponse(w, http.StatusForbidden, "API key doesn't have permission to read webhooks", nil)
			return
		}

		account, err := GetAccountFromContext(r.Context())
		if err != nil {
			JsonResponse(w, http.StatusInternalServerError, "Error retrieving account", err.Error())
			return
		}

		if webhook.AccountID != account.ID {
			JsonResponse(w, http.StatusForbidden, "This webhook belongs to a different account", nil)
			return
		}
	} else {
		if webhook.UserID != user.ID {
			JsonResponse(w, http.StatusForbidden, "You are not authorized to view this webhook", nil)
			return
		}
	}

	// Return without the secret
	webhookWithoutSecret := &WebhookWithoutSecret{
		ID:          webhook.ID,
		UserID:      webhook.UserID,
		AccountID:   webhook.AccountID,
		URL:         webhook.URL,
		Description: webhook.Description,
		Enabled:     webhook.Enabled,
		Events:      webhook.Events,
		CreatedAt:   webhook.CreatedAt,
		UpdatedAt:   webhook.UpdatedAt,
	}

	JsonResponse(w, http.StatusOK, "Webhook retrieved successfully", webhookWithoutSecret)
}

func (h *WebhookHandler) GetByAccount(w http.ResponseWriter, r *http.Request) {
	accountIDStr := chi.URLParam(r, "accountId")
	if accountIDStr == "" {
		JsonResponse(w, http.StatusBadRequest, "Account ID is required", nil)
		return
	}

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

	_, apiKeyErr := GetAPIKeyFromContext(r.Context())
	if apiKeyErr == nil {
		if !CheckAPIPermission(r.Context(), "webhooks", "read") {
			JsonResponse(w, http.StatusForbidden, "API key doesn't have permission to read webhooks", nil)
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
			JsonResponse(w, http.StatusForbidden, "You are not authorized to view webhooks for this account", nil)
			return
		}
	}

	webhooks, err := webhookService.GetByAccount(accountID)
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error retrieving webhooks", err.Error())
		return
	}

	// Return list without secrets
	webhooksWithoutSecrets := make([]*WebhookWithoutSecret, len(webhooks))
	for i, webhook := range webhooks {
		webhooksWithoutSecrets[i] = &WebhookWithoutSecret{
			ID:          webhook.ID,
			UserID:      webhook.UserID,
			AccountID:   webhook.AccountID,
			URL:         webhook.URL,
			Description: webhook.Description,
			Enabled:     webhook.Enabled,
			Events:      webhook.Events,
			CreatedAt:   webhook.CreatedAt,
			UpdatedAt:   webhook.UpdatedAt,
		}
	}

	JsonResponse(w, http.StatusOK, "Webhooks retrieved successfully", webhooksWithoutSecrets)
}

func (h *WebhookHandler) Update(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	if idStr == "" {
		JsonResponse(w, http.StatusBadRequest, "Webhook ID is required", nil)
		return
	}

	id, err := uuid.Parse(idStr)
	if err != nil {
		JsonResponse(w, http.StatusBadRequest, "Invalid webhook ID", err.Error())
		return
	}

	existingWebhook, err := webhookService.Get(id)
	if err != nil {
		JsonResponse(w, http.StatusNotFound, "Webhook not found", err.Error())
		return
	}

	user, err := GetUserFromContext(r.Context())
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error retrieving user", err.Error())
		return
	}

	_, apiKeyErr := GetAPIKeyFromContext(r.Context())
	if apiKeyErr == nil {
		if !CheckAPIPermission(r.Context(), "webhooks", "update") {
			JsonResponse(w, http.StatusForbidden, "API key doesn't have permission to update webhooks", nil)
			return
		}

		account, err := GetAccountFromContext(r.Context())
		if err != nil {
			JsonResponse(w, http.StatusInternalServerError, "Error retrieving account", err.Error())
			return
		}

		if existingWebhook.AccountID != account.ID {
			JsonResponse(w, http.StatusForbidden, "This webhook belongs to a different account", nil)
			return
		}
	} else {
		if existingWebhook.UserID != user.ID {
			JsonResponse(w, http.StatusForbidden, "You are not authorized to update this webhook", nil)
			return
		}
	}

	var input struct {
		URL         string           `json:"url" validate:"omitempty,url"`
		Description string           `json:"description"`
		Events      WebhookEventList `json:"events"`
		Enabled     *bool            `json:"enabled"`
	}

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		JsonResponse(w, http.StatusBadRequest, "Invalid request", err.Error())
		return
	}

	if err := h.Validator.Struct(input); err != nil {
		JsonResponse(w, http.StatusBadRequest, "Invalid request", err.Error())
		return
	}

	if input.URL != "" {
		existingWebhook.URL = input.URL
	}
	existingWebhook.Description = input.Description
	if input.Events != nil {
		existingWebhook.Events = input.Events
	}
	if input.Enabled != nil {
		existingWebhook.Enabled = *input.Enabled
	}
	existingWebhook.UpdatedAt = time.Now()

	err = webhookService.Update(existingWebhook)
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error updating webhook", err.Error())
		return
	}

	// Return without the secret
	webhookWithoutSecret := &WebhookWithoutSecret{
		ID:          existingWebhook.ID,
		UserID:      existingWebhook.UserID,
		AccountID:   existingWebhook.AccountID,
		URL:         existingWebhook.URL,
		Description: existingWebhook.Description,
		Enabled:     existingWebhook.Enabled,
		Events:      existingWebhook.Events,
		CreatedAt:   existingWebhook.CreatedAt,
		UpdatedAt:   existingWebhook.UpdatedAt,
	}

	JsonResponse(w, http.StatusOK, "Webhook updated successfully", webhookWithoutSecret)
}

func (h *WebhookHandler) RegenerateSecret(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	if idStr == "" {
		JsonResponse(w, http.StatusBadRequest, "Webhook ID is required", nil)
		return
	}

	id, err := uuid.Parse(idStr)
	if err != nil {
		JsonResponse(w, http.StatusBadRequest, "Invalid webhook ID", err.Error())
		return
	}

	webhook, err := webhookService.Get(id)
	if err != nil {
		JsonResponse(w, http.StatusNotFound, "Webhook not found", err.Error())
		return
	}

	user, err := GetUserFromContext(r.Context())
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error retrieving user", err.Error())
		return
	}

	_, apiKeyErr := GetAPIKeyFromContext(r.Context())
	if apiKeyErr == nil {
		if !CheckAPIPermission(r.Context(), "webhooks", "update") {
			JsonResponse(w, http.StatusForbidden, "API key doesn't have permission to update webhooks", nil)
			return
		}

		account, err := GetAccountFromContext(r.Context())
		if err != nil {
			JsonResponse(w, http.StatusInternalServerError, "Error retrieving account", err.Error())
			return
		}

		if webhook.AccountID != account.ID {
			JsonResponse(w, http.StatusForbidden, "This webhook belongs to a different account", nil)
			return
		}
	} else {
		if webhook.UserID != user.ID {
			JsonResponse(w, http.StatusForbidden, "You are not authorized to regenerate the secret for this webhook", nil)
			return
		}
	}

	newSecret, err := webhookService.RegenerateSecret(id)
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error regenerating webhook secret", err.Error())
		return
	}

	JsonResponse(w, http.StatusOK, "Webhook secret regenerated successfully", map[string]string{"secret": newSecret})
}

func (h *WebhookHandler) Delete(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	if idStr == "" {
		JsonResponse(w, http.StatusBadRequest, "Webhook ID is required", nil)
		return
	}

	id, err := uuid.Parse(idStr)
	if err != nil {
		JsonResponse(w, http.StatusBadRequest, "Invalid webhook ID", err.Error())
		return
	}

	webhook, err := webhookService.Get(id)
	if err != nil {
		JsonResponse(w, http.StatusNotFound, "Webhook not found", err.Error())
		return
	}

	user, err := GetUserFromContext(r.Context())
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error retrieving user", err.Error())
		return
	}

	_, apiKeyErr := GetAPIKeyFromContext(r.Context())
	if apiKeyErr == nil {
		if !CheckAPIPermission(r.Context(), "webhooks", "delete") {
			JsonResponse(w, http.StatusForbidden, "API key doesn't have permission to delete webhooks", nil)
			return
		}

		account, err := GetAccountFromContext(r.Context())
		if err != nil {
			JsonResponse(w, http.StatusInternalServerError, "Error retrieving account", err.Error())
			return
		}

		if webhook.AccountID != account.ID {
			JsonResponse(w, http.StatusForbidden, "This webhook belongs to a different account", nil)
			return
		}
	} else {
		if webhook.UserID != user.ID {
			JsonResponse(w, http.StatusForbidden, "You are not authorized to delete this webhook", nil)
			return
		}
	}

	err = webhookService.Delete(id)
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error deleting webhook", err.Error())
		return
	}

	JsonResponse(w, http.StatusOK, "Webhook deleted successfully", nil)
}

func (h *WebhookHandler) GetDeliveries(w http.ResponseWriter, r *http.Request) {
	webhookIDStr := chi.URLParam(r, "id")
	if webhookIDStr == "" {
		JsonResponse(w, http.StatusBadRequest, "Webhook ID is required", nil)
		return
	}

	webhookID, err := uuid.Parse(webhookIDStr)
	if err != nil {
		JsonResponse(w, http.StatusBadRequest, "Invalid webhook ID", err.Error())
		return
	}

	webhook, err := webhookService.Get(webhookID)
	if err != nil {
		JsonResponse(w, http.StatusNotFound, "Webhook not found", err.Error())
		return
	}

	user, err := GetUserFromContext(r.Context())
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error retrieving user", err.Error())
		return
	}

	_, apiKeyErr := GetAPIKeyFromContext(r.Context())
	if apiKeyErr == nil {
		if !CheckAPIPermission(r.Context(), "webhooks", "read") {
			JsonResponse(w, http.StatusForbidden, "API key doesn't have permission to read webhook deliveries", nil)
			return
		}

		account, err := GetAccountFromContext(r.Context())
		if err != nil {
			JsonResponse(w, http.StatusInternalServerError, "Error retrieving account", err.Error())
			return
		}

		if webhook.AccountID != account.ID {
			JsonResponse(w, http.StatusForbidden, "This webhook belongs to a different account", nil)
			return
		}
	} else {
		if webhook.UserID != user.ID {
			JsonResponse(w, http.StatusForbidden, "You are not authorized to view deliveries for this webhook", nil)
			return
		}
	}

	limitStr := r.URL.Query().Get("limit")
	offsetStr := r.URL.Query().Get("offset")

	limit := 50 // Default limit
	if limitStr != "" {
		parsedLimit, err := strconv.Atoi(limitStr)
		if err == nil && parsedLimit > 0 {
			limit = parsedLimit
			if limit > 100 {
				limit = 100 // Max limit
			}
		}
	}

	offset := 0 // Default offset
	if offsetStr != "" {
		parsedOffset, err := strconv.Atoi(offsetStr)
		if err == nil && parsedOffset >= 0 {
			offset = parsedOffset
		}
	}

	deliveries, err := webhookService.GetDeliveriesByWebhook(webhookID, limit, offset)
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error retrieving webhook deliveries", err.Error())
		return
	}

	JsonResponse(w, http.StatusOK, "Webhook deliveries retrieved successfully", deliveries)
}

func (h *WebhookHandler) RetryDelivery(w http.ResponseWriter, r *http.Request) {
	deliveryIDStr := chi.URLParam(r, "deliveryId")
	if deliveryIDStr == "" {
		JsonResponse(w, http.StatusBadRequest, "Delivery ID is required", nil)
		return
	}

	deliveryID, err := uuid.Parse(deliveryIDStr)
	if err != nil {
		JsonResponse(w, http.StatusBadRequest, "Invalid delivery ID", err.Error())
		return
	}

	delivery, err := webhookService.GetDelivery(deliveryID)
	if err != nil {
		JsonResponse(w, http.StatusNotFound, "Webhook delivery not found", err.Error())
		return
	}

	webhook, err := webhookService.Get(delivery.WebhookID)
	if err != nil {
		JsonResponse(w, http.StatusNotFound, "Webhook not found", err.Error())
		return
	}

	user, err := GetUserFromContext(r.Context())
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error retrieving user", err.Error())
		return
	}

	_, apiKeyErr := GetAPIKeyFromContext(r.Context())
	if apiKeyErr == nil {
		if !CheckAPIPermission(r.Context(), "webhooks", "update") {
			JsonResponse(w, http.StatusForbidden, "API key doesn't have permission to retry webhook deliveries", nil)
			return
		}

		account, err := GetAccountFromContext(r.Context())
		if err != nil {
			JsonResponse(w, http.StatusInternalServerError, "Error retrieving account", err.Error())
			return
		}

		if webhook.AccountID != account.ID {
			JsonResponse(w, http.StatusForbidden, "This webhook belongs to a different account", nil)
			return
		}
	} else {
		if webhook.UserID != user.ID {
			JsonResponse(w, http.StatusForbidden, "You are not authorized to retry this webhook delivery", nil)
			return
		}
	}

	newDelivery, err := webhookService.RetryDelivery(deliveryID)
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error retrying webhook delivery", err.Error())
		return
	}

	JsonResponse(w, http.StatusOK, "Webhook delivery retry initiated", newDelivery)
}

func init() {
	webhookService = NewWebhookService()
}
