package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
)

type ResourcePermission struct {
	Read   bool `json:"read"`
	Create bool `json:"create"`
	Update bool `json:"update"`
	Delete bool `json:"delete"`
}

type APIKeyPermissions struct {
	Customers     ResourcePermission `json:"customers" validate:"required"`
	Products      ResourcePermission `json:"products" validate:"required"`
	Subscriptions ResourcePermission `json:"subscriptions" validate:"required"`
	PaymentLinks  ResourcePermission `json:"payment_links" validate:"required"`
	Checkouts     ResourcePermission `json:"checkouts" validate:"required"`
	Wallets       ResourcePermission `json:"wallets" validate:"required"`
	Invoices      ResourcePermission `json:"invoices" validate:"required"`
	Webhooks      ResourcePermission `json:"webhooks" validate:"required"`
}

type APIKey struct {
	ID          int               `db:"id" json:"id"`
	UserID      uuid.UUID         `db:"user_id" json:"user_id"`
	AccountID   uuid.UUID         `db:"account_id" json:"account_id"`
	Name        string            `db:"name" json:"name"`
	TokenHash   string            `db:"token_hash" json:"token_hash,omitempty"`
	Permissions APIKeyPermissions `db:"permissions" json:"permissions"`
	CreatedAt   time.Time         `db:"created_at" json:"created_at"`
	UpdatedAt   time.Time         `db:"updated_at" json:"updated_at"`
	LastUsedAt  *time.Time        `db:"last_used_at" json:"last_used_at,omitempty"`
	DeletedAt   *time.Time        `db:"deleted_at" json:"deleted_at,omitempty"`
	LockedAt    *time.Time        `db:"locked_at" json:"locked_at,omitempty"`
}

type APIKeyWithToken struct {
	APIKey
	Token string `json:"token"`
}

type APIKeyCache struct {
	cache sync.Map
}

func (c *APIKeyCache) Get(tokenHash string) (*APIKey, bool) {
	value, ok := c.cache.Load(tokenHash)
	if !ok {
		return nil, false
	}
	apiKey, ok := value.(*APIKey)
	return apiKey, ok
}

func (c *APIKeyCache) Set(apiKey *APIKey) {
	if apiKey != nil {
		c.cache.Store(apiKey.TokenHash, apiKey)
	}
}

func (c *APIKeyCache) Delete(tokenHash string) {
	c.cache.Delete(tokenHash)
}

type APIKeyRepository struct{}

func (r *APIKeyRepository) Create(apiKey *APIKey) (*APIKey, error) {
	permissionsJSON, err := json.Marshal(apiKey.Permissions)
	if err != nil {
		return nil, err
	}

	err = db.QueryRowx(`
		INSERT INTO api_keys (
			user_id, account_id, name, token_hash, permissions, 
			created_at, updated_at, last_used_at, deleted_at, locked_at
		) VALUES (
			$1, $2, $3, $4, $5, 
			$6, $7, $8, $9, $10
		) RETURNING id`,
		apiKey.UserID, apiKey.AccountID, apiKey.Name, apiKey.TokenHash, permissionsJSON,
		apiKey.CreatedAt, apiKey.UpdatedAt, apiKey.LastUsedAt, apiKey.DeletedAt, apiKey.LockedAt,
	).Scan(&apiKey.ID)

	return apiKey, err
}

func (r *APIKeyRepository) Get(id int) (*APIKey, error) {
	apiKey := &APIKey{}
	var permissionsJSON []byte

	err := db.QueryRowx(`
		SELECT id, user_id, account_id, name, token_hash, permissions, 
			created_at, updated_at, last_used_at, deleted_at, locked_at
		FROM api_keys
		WHERE id = $1 AND deleted_at IS NULL`,
		id,
	).Scan(
		&apiKey.ID, &apiKey.UserID, &apiKey.AccountID, &apiKey.Name, &apiKey.TokenHash, &permissionsJSON,
		&apiKey.CreatedAt, &apiKey.UpdatedAt, &apiKey.LastUsedAt, &apiKey.DeletedAt, &apiKey.LockedAt,
	)

	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(permissionsJSON, &apiKey.Permissions)
	if err != nil {
		return nil, err
	}

	return apiKey, nil
}

func (r *APIKeyRepository) GetByHash(tokenHash string) (*APIKey, error) {
	apiKey := &APIKey{}
	var permissionsJSON []byte

	err := db.QueryRowx(`
		SELECT id, user_id, account_id, name, token_hash, permissions, 
			created_at, updated_at, last_used_at, deleted_at, locked_at
		FROM api_keys
		WHERE token_hash = $1 AND deleted_at IS NULL AND locked_at IS NULL`,
		tokenHash,
	).Scan(
		&apiKey.ID, &apiKey.UserID, &apiKey.AccountID, &apiKey.Name, &apiKey.TokenHash, &permissionsJSON,
		&apiKey.CreatedAt, &apiKey.UpdatedAt, &apiKey.LastUsedAt, &apiKey.DeletedAt, &apiKey.LockedAt,
	)

	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(permissionsJSON, &apiKey.Permissions)
	if err != nil {
		return nil, err
	}

	return apiKey, nil
}

func (r *APIKeyRepository) GetByUser(userID uuid.UUID) ([]*APIKey, error) {
	rows, err := db.Queryx(`
		SELECT id, user_id, account_id, name, permissions, 
			created_at, updated_at, last_used_at, deleted_at, locked_at
		FROM api_keys
		WHERE user_id = $1 AND deleted_at IS NULL
		ORDER BY created_at DESC`,
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var apiKeys []*APIKey
	for rows.Next() {
		apiKey := &APIKey{}
		var permissionsJSON []byte

		err := rows.Scan(
			&apiKey.ID, &apiKey.UserID, &apiKey.AccountID, &apiKey.Name, &permissionsJSON,
			&apiKey.CreatedAt, &apiKey.UpdatedAt, &apiKey.LastUsedAt, &apiKey.DeletedAt, &apiKey.LockedAt,
		)
		if err != nil {
			return nil, err
		}

		err = json.Unmarshal(permissionsJSON, &apiKey.Permissions)
		if err != nil {
			return nil, err
		}

		apiKeys = append(apiKeys, apiKey)
	}

	return apiKeys, nil
}

func (r *APIKeyRepository) GetByAccount(accountID uuid.UUID) ([]*APIKey, error) {
	rows, err := db.Queryx(`
		SELECT id, user_id, account_id, name, permissions, 
			created_at, updated_at, last_used_at, deleted_at, locked_at
		FROM api_keys
		WHERE account_id = $1 AND deleted_at IS NULL
		ORDER BY created_at DESC`,
		accountID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var apiKeys []*APIKey
	for rows.Next() {
		apiKey := &APIKey{}
		var permissionsJSON []byte

		err := rows.Scan(
			&apiKey.ID, &apiKey.UserID, &apiKey.AccountID, &apiKey.Name, &permissionsJSON,
			&apiKey.CreatedAt, &apiKey.UpdatedAt, &apiKey.LastUsedAt, &apiKey.DeletedAt, &apiKey.LockedAt,
		)
		if err != nil {
			return nil, err
		}

		err = json.Unmarshal(permissionsJSON, &apiKey.Permissions)
		if err != nil {
			return nil, err
		}

		apiKeys = append(apiKeys, apiKey)
	}

	return apiKeys, nil
}

func (r *APIKeyRepository) Update(apiKey *APIKey) error {
	permissionsJSON, err := json.Marshal(apiKey.Permissions)
	if err != nil {
		return err
	}

	_, err = db.Exec(`
		UPDATE api_keys SET 
			name = $1, 
			permissions = $2,
			updated_at = $3,
			locked_at = $4,
			deleted_at = $5
		WHERE id = $6`,
		apiKey.Name, permissionsJSON, apiKey.UpdatedAt, apiKey.LockedAt, apiKey.DeletedAt, apiKey.ID,
	)
	return err
}

func (r *APIKeyRepository) UpdateLastUsed(id int) error {
	now := time.Now()
	_, err := db.Exec(`
		UPDATE api_keys SET 
			last_used_at = $1
		WHERE id = $2`,
		now, id,
	)
	return err
}

func (r *APIKeyRepository) Delete(id int) error {
	now := time.Now()
	_, err := db.Exec(`
		UPDATE api_keys SET 
			deleted_at = $1
		WHERE id = $2`,
		now, id,
	)
	return err
}

func (r *APIKeyRepository) Lock(id int) error {
	now := time.Now()
	_, err := db.Exec(`
		UPDATE api_keys SET 
			locked_at = $1
		WHERE id = $2`,
		now, id,
	)
	return err
}

type APIKeyService struct{}

var apiKeyRepository = &APIKeyRepository{}
var apiKeyCache = &APIKeyCache{}
var apiKeyService = &APIKeyService{}

func (s *APIKeyService) HashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

func (s *APIKeyService) GenerateToken(id int) string {
	return fmt.Sprintf("%d|%s", id, uuid.New().String())
}

func (s *APIKeyService) Create(apiKey *APIKey) (*APIKeyWithToken, error) {
	apiKey.CreatedAt = time.Now()
	apiKey.UpdatedAt = time.Now()

	createdAPIKey, err := apiKeyRepository.Create(apiKey)
	if err != nil {
		return nil, err
	}

	token := s.GenerateToken(createdAPIKey.ID)
	tokenHash := s.HashToken(token)

	createdAPIKey.TokenHash = tokenHash
	_, err = db.Exec(`
		UPDATE api_keys SET 
			token_hash = $1
		WHERE id = $2`,
		tokenHash, createdAPIKey.ID,
	)
	if err != nil {
		return nil, err
	}

	apiKeyCache.Set(createdAPIKey)

	return &APIKeyWithToken{
		APIKey: *createdAPIKey,
		Token:  token,
	}, nil
}

func (s *APIKeyService) Get(id int) (*APIKey, error) {
	return apiKeyRepository.Get(id)
}

func (s *APIKeyService) GetByToken(token string) (*APIKey, error) {
	tokenHash := s.HashToken(token)

	if cachedAPIKey, found := apiKeyCache.Get(tokenHash); found && cachedAPIKey != nil {
		return cachedAPIKey, nil
	}

	apiKey, err := apiKeyRepository.GetByHash(tokenHash)
	if err != nil {
		return nil, err
	}

	err = apiKeyRepository.UpdateLastUsed(apiKey.ID)
	if err != nil {
		fmt.Printf("Failed to update last used timestamp for API key %d: %v\n", apiKey.ID, err)
	}

	apiKeyCache.Set(apiKey)

	return apiKey, nil
}

func (s *APIKeyService) GetByUser(userID uuid.UUID) ([]*APIKey, error) {
	return apiKeyRepository.GetByUser(userID)
}

func (s *APIKeyService) GetByAccount(accountID uuid.UUID) ([]*APIKey, error) {
	return apiKeyRepository.GetByAccount(accountID)
}

func (s *APIKeyService) Update(apiKey *APIKey) error {
	apiKey.UpdatedAt = time.Now()

	err := apiKeyRepository.Update(apiKey)
	if err != nil {
		return err
	}

	if apiKey.TokenHash != "" {
		apiKeyCache.Set(apiKey)
	}

	return nil
}

func (s *APIKeyService) Delete(id int) error {
	apiKey, err := apiKeyRepository.Get(id)
	if err != nil {
		return err
	}

	err = apiKeyRepository.Delete(id)
	if err != nil {
		return err
	}

	if apiKey.TokenHash != "" {
		apiKeyCache.Delete(apiKey.TokenHash)
	}

	return nil
}

func (s *APIKeyService) Lock(id int) error {
	apiKey, err := apiKeyRepository.Get(id)
	if err != nil {
		return err
	}

	err = apiKeyRepository.Lock(id)
	if err != nil {
		return err
	}

	if apiKey.TokenHash != "" {
		apiKeyCache.Delete(apiKey.TokenHash)
	}

	return nil
}

func (s *APIKeyService) ParseAPIKey(apiKeyStr string) (int, string, error) {
	parts := strings.SplitN(apiKeyStr, "|", 2)
	if len(parts) != 2 {
		return 0, "", fmt.Errorf("invalid API key format")
	}

	id := 0
	_, err := fmt.Sscanf(parts[0], "%d", &id)
	if err != nil {
		return 0, "", fmt.Errorf("invalid API key ID: %w", err)
	}

	return id, parts[1], nil
}

type APIKeyHandler struct {
	Validator *validator.Validate
}

var apiKeyHandler = &APIKeyHandler{
	Validator: validator.New(),
}

func (h *APIKeyHandler) Create(w http.ResponseWriter, r *http.Request) {
	var input struct {
		AccountID   uuid.UUID         `json:"account_id" validate:"required"`
		Name        string            `json:"name" validate:"required"`
		Permissions APIKeyPermissions `json:"permissions" validate:"required"`
	}

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		JsonResponse(w, http.StatusBadRequest, "Invalid request format", err.Error())
		return
	}

	// Set default validation
	validate := validator.New()

	// Register a custom struct validation if needed
	// validate.RegisterStructValidation(...)

	if err := validate.Struct(input); err != nil {
		JsonResponse(w, http.StatusBadRequest, "Invalid request data", err.Error())
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
		JsonResponse(w, http.StatusForbidden, "You are not authorized to create API keys for this account", nil)
		return
	}

	apiKey := &APIKey{
		UserID:      user.ID,
		AccountID:   input.AccountID,
		Name:        input.Name,
		Permissions: input.Permissions,
	}

	createdAPIKey, err := apiKeyService.Create(apiKey)
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error creating API key", err.Error())
		return
	}

	JsonResponse(w, http.StatusCreated, "API key created successfully", createdAPIKey)
}

func (h *APIKeyHandler) Get(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	if idStr == "" {
		JsonResponse(w, http.StatusBadRequest, "API key ID is required", nil)
		return
	}

	id := 0
	_, err := fmt.Sscanf(idStr, "%d", &id)
	if err != nil {
		JsonResponse(w, http.StatusBadRequest, "Invalid API key ID", err.Error())
		return
	}

	apiKey, err := apiKeyService.Get(id)
	if err != nil {
		JsonResponse(w, http.StatusNotFound, "API key not found", err.Error())
		return
	}

	user, err := GetUserFromContext(r.Context())
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error retrieving user", err.Error())
		return
	}

	if apiKey.UserID != user.ID {
		JsonResponse(w, http.StatusForbidden, "You are not authorized to view this API key", nil)
		return
	}

	apiKey.TokenHash = ""

	JsonResponse(w, http.StatusOK, "API key retrieved successfully", apiKey)
}

func (h *APIKeyHandler) GetByAccount(w http.ResponseWriter, r *http.Request) {
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
		JsonResponse(w, http.StatusForbidden, "You are not authorized to view API keys for this account", nil)
		return
	}

	apiKeys, err := apiKeyService.GetByAccount(accountID)
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error retrieving API keys", err.Error())
		return
	}

	for _, apiKey := range apiKeys {
		apiKey.TokenHash = ""
	}

	JsonResponse(w, http.StatusOK, "API keys retrieved successfully", apiKeys)
}

func (h *APIKeyHandler) GetAll(w http.ResponseWriter, r *http.Request) {
	user, err := GetUserFromContext(r.Context())
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error retrieving user", err.Error())
		return
	}

	apiKeys, err := apiKeyService.GetByUser(user.ID)
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error retrieving API keys", err.Error())
		return
	}

	for _, apiKey := range apiKeys {
		apiKey.TokenHash = ""
	}

	JsonResponse(w, http.StatusOK, "API keys retrieved successfully", apiKeys)
}

func (h *APIKeyHandler) Update(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	if idStr == "" {
		JsonResponse(w, http.StatusBadRequest, "API key ID is required", nil)
		return
	}

	id := 0
	_, err := fmt.Sscanf(idStr, "%d", &id)
	if err != nil {
		JsonResponse(w, http.StatusBadRequest, "Invalid API key ID", err.Error())
		return
	}

	apiKey, err := apiKeyService.Get(id)
	if err != nil {
		JsonResponse(w, http.StatusNotFound, "API key not found", err.Error())
		return
	}

	user, err := GetUserFromContext(r.Context())
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error retrieving user", err.Error())
		return
	}

	if apiKey.UserID != user.ID {
		JsonResponse(w, http.StatusForbidden, "You are not authorized to update this API key", nil)
		return
	}

	var input struct {
		Name        string            `json:"name" validate:"required"`
		Permissions APIKeyPermissions `json:"permissions" validate:"required"`
	}

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		JsonResponse(w, http.StatusBadRequest, "Invalid request", err.Error())
		return
	}

	if err := h.Validator.Struct(input); err != nil {
		JsonResponse(w, http.StatusBadRequest, "Invalid request", err.Error())
		return
	}

	apiKey.Name = input.Name
	apiKey.Permissions = input.Permissions

	err = apiKeyService.Update(apiKey)
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error updating API key", err.Error())
		return
	}

	apiKey.TokenHash = ""

	JsonResponse(w, http.StatusOK, "API key updated successfully", apiKey)
}

func (h *APIKeyHandler) Delete(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	if idStr == "" {
		JsonResponse(w, http.StatusBadRequest, "API key ID is required", nil)
		return
	}

	id := 0
	_, err := fmt.Sscanf(idStr, "%d", &id)
	if err != nil {
		JsonResponse(w, http.StatusBadRequest, "Invalid API key ID", err.Error())
		return
	}

	apiKey, err := apiKeyService.Get(id)
	if err != nil {
		JsonResponse(w, http.StatusNotFound, "API key not found", err.Error())
		return
	}

	user, err := GetUserFromContext(r.Context())
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error retrieving user", err.Error())
		return
	}

	if apiKey.UserID != user.ID {
		JsonResponse(w, http.StatusForbidden, "You are not authorized to delete this API key", nil)
		return
	}

	err = apiKeyService.Delete(id)
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error deleting API key", err.Error())
		return
	}

	JsonResponse(w, http.StatusOK, "API key deleted successfully", nil)
}

func (h *APIKeyHandler) Lock(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	if idStr == "" {
		JsonResponse(w, http.StatusBadRequest, "API key ID is required", nil)
		return
	}

	id := 0
	_, err := fmt.Sscanf(idStr, "%d", &id)
	if err != nil {
		JsonResponse(w, http.StatusBadRequest, "Invalid API key ID", err.Error())
		return
	}

	apiKey, err := apiKeyService.Get(id)
	if err != nil {
		JsonResponse(w, http.StatusNotFound, "API key not found", err.Error())
		return
	}

	user, err := GetUserFromContext(r.Context())
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error retrieving user", err.Error())
		return
	}

	if apiKey.UserID != user.ID {
		JsonResponse(w, http.StatusForbidden, "You are not authorized to lock this API key", nil)
		return
	}

	err = apiKeyService.Lock(id)
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error locking API key", err.Error())
		return
	}

	JsonResponse(w, http.StatusOK, "API key locked successfully", nil)
}

func AuthenticateAPIKey(token string) (*APIKey, error) {
	return apiKeyService.GetByToken(token)
}

func APIKeyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			next.ServeHTTP(w, r)
			return
		}

		if !strings.HasPrefix(authHeader, "Bearer ") {
			next.ServeHTTP(w, r)
			return
		}

		token := strings.TrimPrefix(authHeader, "Bearer ")

		apiKey, err := AuthenticateAPIKey(token)
		if err != nil {
			next.ServeHTTP(w, r)
			return
		}

		user, err := userService.Get(apiKey.UserID)
		if err != nil {
			next.ServeHTTP(w, r)
			return
		}

		ctx := r.Context()
		ctx = context.WithValue(ctx, UserContextKey, user)
		ctx = context.WithValue(ctx, "api_key", apiKey)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func DefaultPermissions() APIKeyPermissions {
	return APIKeyPermissions{
		Customers: ResourcePermission{
			Read:   true,
			Create: true,
			Update: true,
			Delete: true,
		},
		Products: ResourcePermission{
			Read:   true,
			Create: true,
			Update: true,
			Delete: true,
		},
		Subscriptions: ResourcePermission{
			Read:   true,
			Create: true,
			Update: true,
			Delete: true,
		},
		PaymentLinks: ResourcePermission{
			Read:   true,
			Create: true,
			Update: true,
			Delete: true,
		},
		Checkouts: ResourcePermission{
			Read:   true,
			Create: true,
			Update: true,
			Delete: true,
		},
		Wallets: ResourcePermission{
			Read:   true,
			Create: true,
			Update: true,
			Delete: true,
		},
		Invoices: ResourcePermission{
			Read:   true,
			Create: true,
			Update: true,
			Delete: true,
		},
		Webhooks: ResourcePermission{
			Read:   true,
			Create: true,
			Update: true,
			Delete: true,
		},
	}
}
