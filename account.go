package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
)

type Account struct {
	ID           uuid.UUID  `db:"id" json:"id"`
	UserID       uuid.UUID  `db:"user_id" json:"user_id"`
	Name         string     `db:"name" json:"name"`
	Logo         *string    `db:"logo" json:"logo,omitempty"`
	AddressLine1 *string    `db:"address_line1" json:"address_line1,omitempty"`
	AddressLine2 *string    `db:"address_line2" json:"address_line2,omitempty"`
	City         *string    `db:"city" json:"city,omitempty"`
	State        *string    `db:"state" json:"state,omitempty"`
	PostalCode   *string    `db:"postal_code" json:"postal_code,omitempty"`
	Country      *string    `db:"country" json:"country,omitempty"`
	CreatedAt    time.Time  `db:"created_at" json:"created_at"`
	UpdatedAt    time.Time  `db:"updated_at" json:"updated_at"`
	DeletedAt    *time.Time `db:"deleted_at" json:"deleted_at,omitempty"`
}

type AccountCache struct {
	cache sync.Map
}

func (c *AccountCache) Get(id uuid.UUID) (*Account, bool) {
	value, ok := c.cache.Load(id)
	if !ok {
		return nil, false
	}
	account, ok := value.(*Account)
	return account, ok
}

func (c *AccountCache) Set(account *Account) {
	if account != nil {
		c.cache.Store(account.ID, account)
	}
}

type AccountRepository struct{}
type AccountService struct{}

var accountRepository = &AccountRepository{}
var accountCache = &AccountCache{}
var accountService = &AccountService{}

func (r *AccountRepository) Create(account *Account) (*Account, error) {
	err := db.Get(account, `
		INSERT INTO accounts (
			id, user_id, name, logo, 
			address_line1, address_line2, city, state, postal_code, country,
			created_at, updated_at, deleted_at
		) VALUES (
			$1, $2, $3, $4, 
			$5, $6, $7, $8, $9, $10,
			$11, $12, $13
		) RETURNING *`,
		account.ID, account.UserID, account.Name, account.Logo,
		account.AddressLine1, account.AddressLine2, account.City, account.State, account.PostalCode, account.Country,
		account.CreatedAt, account.UpdatedAt, account.DeletedAt)
	return account, err
}

func (r *AccountRepository) Update(account *Account) error {
	_, err := db.Exec(`
		UPDATE accounts SET 
			name=$1, logo=$2,
			address_line1=$3, address_line2=$4, city=$5, state=$6, postal_code=$7, country=$8,
			updated_at=$9, deleted_at=$10 
		WHERE id=$11`,
		account.Name, account.Logo,
		account.AddressLine1, account.AddressLine2, account.City, account.State, account.PostalCode, account.Country,
		account.UpdatedAt, account.DeletedAt, account.ID)
	return err
}

func (r *AccountRepository) Get(id uuid.UUID) (*Account, error) {
	account := &Account{}
	err := db.Get(account, "SELECT * FROM accounts WHERE id=$1 AND deleted_at IS NULL", id)
	return account, err
}

func (r *AccountRepository) GetByUser(userID uuid.UUID) ([]*Account, error) {
	accounts := []*Account{}
	err := db.Select(&accounts, "SELECT * FROM accounts WHERE user_id=$1 AND deleted_at IS NULL ORDER BY created_at DESC", userID)
	return accounts, err
}

func (r *AccountRepository) Delete(id uuid.UUID) error {
	_, err := db.Exec("UPDATE accounts SET deleted_at=$1 WHERE id=$2", time.Now(), id)
	return err
}

func (s *AccountService) Create(account *Account) (*Account, error) {
	account.CreatedAt = time.Now()
	account.UpdatedAt = time.Now()

	createdAccount, err := accountRepository.Create(account)
	if err == nil && createdAccount != nil {
		accountCache.Set(createdAccount)
	}
	return createdAccount, err
}

func (s *AccountService) Update(account *Account) error {
	account.UpdatedAt = time.Now()

	err := accountRepository.Update(account)
	if err == nil {
		accountCache.Set(account)
	}
	return err
}

func (s *AccountService) Get(id uuid.UUID) (*Account, error) {
	if cachedAccount, found := accountCache.Get(id); found && cachedAccount != nil {
		return cachedAccount, nil
	}

	account, err := accountRepository.Get(id)
	if err == nil && account != nil {
		accountCache.Set(account)
	}
	return account, err
}

func (s *AccountService) GetByUser(userID uuid.UUID) ([]*Account, error) {
	return accountRepository.GetByUser(userID)
}

func (s *AccountService) Delete(id uuid.UUID) error {
	err := accountRepository.Delete(id)
	if err == nil {
		accountCache.cache.Delete(id)
	}
	return err
}

type AccountHandler struct {
	Validator *validator.Validate
}

var accountHandler = &AccountHandler{
	Validator: validator.New(),
}

func (h *AccountHandler) Create(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Name         string  `json:"name" validate:"required"`
		Logo         *string `json:"logo,omitempty"`
		AddressLine1 *string `json:"address_line1,omitempty"`
		AddressLine2 *string `json:"address_line2,omitempty"`
		City         *string `json:"city,omitempty"`
		State        *string `json:"state,omitempty"`
		PostalCode   *string `json:"postal_code,omitempty"`
		Country      *string `json:"country,omitempty"`
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

	account := &Account{
		ID:           uuid.New(),
		UserID:       user.ID,
		Name:         input.Name,
		Logo:         input.Logo,
		AddressLine1: input.AddressLine1,
		AddressLine2: input.AddressLine2,
		City:         input.City,
		State:        input.State,
		PostalCode:   input.PostalCode,
		Country:      input.Country,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	createdAccount, err := accountService.Create(account)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	JsonResponse(w, http.StatusCreated, "Account created successfully", createdAccount)
}

func (h *AccountHandler) Update(w http.ResponseWriter, r *http.Request) {
	accountIDStr := chi.URLParam(r, "id")
	fmt.Printf("Received account ID: %s\n", accountIDStr)

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
		JsonResponse(w, http.StatusInternalServerError, "Error retrieving account", err.Error())
		return
	}

	if account.UserID != user.ID {
		JsonResponse(w, http.StatusForbidden, "You are not authorized to update this account", nil)
		return
	}

	var input struct {
		Name         string  `json:"name" validate:"required"`
		Logo         *string `json:"logo,omitempty"`
		AddressLine1 *string `json:"address_line1,omitempty"`
		AddressLine2 *string `json:"address_line2,omitempty"`
		City         *string `json:"city,omitempty"`
		State        *string `json:"state,omitempty"`
		PostalCode   *string `json:"postal_code,omitempty"`
		Country      *string `json:"country,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		JsonResponse(w, http.StatusBadRequest, "Invalid request", err.Error())
		return
	}

	if err := h.Validator.Struct(input); err != nil {
		JsonResponse(w, http.StatusBadRequest, "Invalid request", err.Error())
		return
	}

	account = &Account{
		ID:           account.ID,
		UserID:       account.UserID,
		Name:         input.Name,
		Logo:         input.Logo,
		AddressLine1: input.AddressLine1,
		AddressLine2: input.AddressLine2,
		City:         input.City,
		State:        input.State,
		PostalCode:   input.PostalCode,
		Country:      input.Country,
		UpdatedAt:    time.Now(),
	}
	err = accountService.Update(account)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	JsonResponse(w, http.StatusOK, "Account updated successfully", account)
}

func (h *AccountHandler) Get(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		JsonResponse(w, http.StatusBadRequest, "Invalid account ID", nil)
		return
	}

	account, err := accountService.Get(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	JsonResponse(w, http.StatusOK, "Account retrieved successfully", account)
}

func (h *AccountHandler) GetAll(w http.ResponseWriter, r *http.Request) {
	user, err := GetUserFromContext(r.Context())
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error retrieving user", err.Error())
		return
	}

	accounts, err := accountService.GetByUser(user.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	JsonResponse(w, http.StatusOK, "Accounts retrieved successfully", accounts)
}

func (h *AccountHandler) Delete(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		JsonResponse(w, http.StatusBadRequest, "Invalid account ID", nil)
		return
	}

	err = accountService.Delete(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	JsonResponse(w, http.StatusOK, "Account deleted successfully", nil)
}
