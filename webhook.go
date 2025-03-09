package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"database/sql/driver"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
)

type WebhookEvent string

const (
	WebhookEventCheckoutCreated      WebhookEvent = "checkout.created"
	WebhookEventCheckoutPaid         WebhookEvent = "checkout.paid"
	WebhookEventCheckoutUnderpaid    WebhookEvent = "checkout.underpaid"
	WebhookEventCheckoutOverpaid     WebhookEvent = "checkout.overpaid"
	WebhookEventCheckoutExpired      WebhookEvent = "checkout.expired"
	WebhookEventSubscriptionCreated  WebhookEvent = "subscription.created"
	WebhookEventSubscriptionUpdated  WebhookEvent = "subscription.updated"
	WebhookEventSubscriptionCanceled WebhookEvent = "subscription.canceled"
)

var AllWebhookEvents = []WebhookEvent{
	WebhookEventCheckoutCreated,
	WebhookEventCheckoutPaid,
	WebhookEventCheckoutUnderpaid,
	WebhookEventCheckoutOverpaid,
	WebhookEventCheckoutExpired,
	WebhookEventSubscriptionCreated,
	WebhookEventSubscriptionUpdated,
	WebhookEventSubscriptionCanceled,
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
			signature := s.GenerateSignature(payloadBytes, wh.Secret)

			req, err := http.NewRequest("POST", wh.URL, bytes.NewBuffer(payloadBytes))
			if err != nil {
				fmt.Printf("Error creating webhook request: %v\n", err)
				return
			}

			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Signature", signature)
			req.Header.Set("X-Webhook-ID", fmt.Sprintf("%s", wh.ID))
			req.Header.Set("X-Event", string(event))

			resp, err := s.httpClient.Do(req)
			if err != nil {
				fmt.Printf("Error delivering webhook: %v\n", err)
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode >= 300 {
				fmt.Printf("Webhook delivery error: status code %d\n", resp.StatusCode)
			}
		}(webhook)
	}
}

type WebhookHandler struct {
	Validator *validator.Validate
}

var webhookHandler = &WebhookHandler{
	Validator: validator.New(),
}

func (h *WebhookHandler) Create(w http.ResponseWriter, r *http.Request) {
	var input struct {
		AccountID   uuid.UUID      `json:"account_id" validate:"required"`
		URL         string         `json:"url" validate:"required,url"`
		Description string         `json:"description"`
		Events      []WebhookEvent `json:"events" validate:"required"`
	}

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		JsonResponse(w, http.StatusBadRequest, "Invalid request format", err.Error())
		return
	}

	if err := h.Validator.Struct(input); err != nil {
		JsonResponse(w, http.StatusBadRequest, "Invalid request data", err.Error())
		return
	}

	validEvents := make(map[string]bool)
	for _, event := range AllWebhookEvents {
		validEvents[string(event)] = true
	}

	for _, event := range input.Events {
		if !validEvents[string(event)] {
			JsonResponse(w, http.StatusBadRequest, "Invalid event type", fmt.Sprintf("Event '%s' is not a valid event type", event))
			return
		}
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
		JsonResponse(w, http.StatusForbidden, "You are not authorized to create webhooks for this account", nil)
		return
	}

	webhook := &Webhook{
		UserID:      user.ID,
		AccountID:   input.AccountID,
		URL:         input.URL,
		Description: input.Description,
		Enabled:     true,
		Events:      input.Events,
	}

	createdWebhook, err := webhookService.Create(webhook)
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error creating webhook", err.Error())
		return
	}

	JsonResponse(w, http.StatusCreated, "Webhook created successfully", createdWebhook)
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

	if webhook.UserID != user.ID {
		JsonResponse(w, http.StatusForbidden, "You are not authorized to view this webhook", nil)
		return
	}

	webhookResponse := WebhookWithoutSecret{
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

	JsonResponse(w, http.StatusOK, "Webhook retrieved successfully", webhookResponse)
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

	account, err := accountService.Get(accountID)
	if err != nil {
		JsonResponse(w, http.StatusNotFound, "Account not found", err.Error())
		return
	}

	if account.UserID != user.ID {
		JsonResponse(w, http.StatusForbidden, "You are not authorized to view webhooks for this account", nil)
		return
	}

	webhooks, err := webhookService.GetByAccount(accountID)
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error retrieving webhooks", err.Error())
		return
	}

	webhooksResponse := make([]WebhookWithoutSecret, len(webhooks))
	for i, webhook := range webhooks {
		webhooksResponse[i] = WebhookWithoutSecret{
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

	JsonResponse(w, http.StatusOK, "Webhooks retrieved successfully", webhooksResponse)
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

	if webhook.UserID != user.ID {
		JsonResponse(w, http.StatusForbidden, "You are not authorized to update this webhook", nil)
		return
	}

	var input struct {
		URL         string         `json:"url" validate:"required,url"`
		Description string         `json:"description"`
		Enabled     bool           `json:"enabled"`
		Events      []WebhookEvent `json:"events" validate:"required"`
	}

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		JsonResponse(w, http.StatusBadRequest, "Invalid request format", err.Error())
		return
	}

	if err := h.Validator.Struct(input); err != nil {
		JsonResponse(w, http.StatusBadRequest, "Invalid request data", err.Error())
		return
	}

	validEvents := make(map[string]bool)
	for _, event := range AllWebhookEvents {
		validEvents[string(event)] = true
	}

	for _, event := range input.Events {
		if !validEvents[string(event)] {
			JsonResponse(w, http.StatusBadRequest, "Invalid event type", fmt.Sprintf("Event '%s' is not a valid event type", event))
			return
		}
	}

	webhook.URL = input.URL
	webhook.Description = input.Description
	webhook.Enabled = input.Enabled
	webhook.Events = input.Events

	err = webhookService.Update(webhook)
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error updating webhook", err.Error())
		return
	}

	webhookResponse := WebhookWithoutSecret{
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

	JsonResponse(w, http.StatusOK, "Webhook updated successfully", webhookResponse)
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

	if webhook.UserID != user.ID {
		JsonResponse(w, http.StatusForbidden, "You are not authorized to regenerate the secret for this webhook", nil)
		return
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

	if webhook.UserID != user.ID {
		JsonResponse(w, http.StatusForbidden, "You are not authorized to delete this webhook", nil)
		return
	}

	err = webhookService.Delete(id)
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error deleting webhook", err.Error())
		return
	}

	JsonResponse(w, http.StatusOK, "Webhook deleted successfully", nil)
}

func init() {
	webhookService = NewWebhookService()
}
