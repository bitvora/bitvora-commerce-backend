package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID          uuid.UUID  `db:"id" json:"id"`
	Email       string     `db:"email" json:"email"`
	Password    string     `db:"password" json:"password"`
	TOTPSecret  *string    `db:"totp_secret" json:"totp_secret,omitempty"`
	LastLoginAt *time.Time `db:"last_login_at" json:"last_login_at,omitempty"`
	CreatedAt   time.Time  `db:"created_at" json:"created_at"`
	UpdatedAt   time.Time  `db:"updated_at" json:"updated_at"`
	DeletedAt   *time.Time `db:"deleted_at" json:"deleted_at,omitempty"`
}

type UserCache struct {
	cache sync.Map
}

func (c *UserCache) Get(id uuid.UUID) (*User, bool) {
	value, ok := c.cache.Load(id)
	if !ok {
		return nil, false
	}
	user, ok := value.(*User)
	return user, ok
}

func (c *UserCache) Set(user *User) {
	if user != nil {
		c.cache.Store(user.ID, user)
	}
}

type UserRepository struct{}
type UserService struct{}
type UserHandler struct {
	Validator *validator.Validate
}

var userRepository = &UserRepository{}
var userCache = &UserCache{}
var userService = &UserService{}
var userHandler = &UserHandler{
	Validator: validator.New(),
}

func (r *UserRepository) Create(user *User) (*User, error) {
	err := db.Get(user, "INSERT INTO users (id, email, password, totp_secret, last_login_at, created_at, updated_at, deleted_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *", user.ID, user.Email, user.Password, user.TOTPSecret, user.LastLoginAt, user.CreatedAt, user.UpdatedAt, user.DeletedAt)
	return user, err
}

func (r *UserRepository) Update(user *User) error {
	_, err := db.Exec("UPDATE users SET email=$1, password=$2, totp_secret=$3, last_login_at=$4, updated_at=$5, deleted_at=$6 WHERE id=$7", user.Email, user.Password, user.TOTPSecret, user.LastLoginAt, user.UpdatedAt, user.DeletedAt, user.ID)
	return err
}

func (r *UserRepository) Get(id uuid.UUID) (*User, error) {
	user := &User{}
	err := db.Get(user, "SELECT * FROM users WHERE id=$1", id)
	return user, err
}

func (r *UserRepository) GetByEmail(email string) (*User, error) {
	user := &User{}
	err := db.Get(user, "SELECT * FROM users WHERE email=$1", email)
	return user, err
}

func (r *UserRepository) Delete(id uuid.UUID) error {
	_, err := db.Exec("DELETE FROM users WHERE id=$1", id)
	return err
}

func (s *UserService) Create(user *User) (*User, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	user.Password = string(hashedPassword)

	createdUser, err := userRepository.Create(user)
	if err == nil && createdUser != nil {
		userCache.Set(createdUser)
	}
	return createdUser, err
}

func (s *UserService) CreateWalletForUser(user *User, password string) error {
	// Check if NEW_WALLET_ENDPOINT is set
	endpoint := os.Getenv("NEW_WALLET_ENDPOINT")
	if endpoint == "" {
		// Skip wallet creation if endpoint is not set
		return nil
	}

	// Get shared secret from environment variable
	secret := os.Getenv("NEW_WALLET_API_SECRET")
	if secret == "" {
		return fmt.Errorf("NEW_WALLET_API_SECRET is not set")
	}

	// Generate timestamp
	timestamp := time.Now().Unix()

	// Calculate signature
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(user.Email + strconv.FormatInt(timestamp, 10)))
	signature := hex.EncodeToString(h.Sum(nil))

	// Create request body
	requestBody, err := json.Marshal(map[string]interface{}{
		"email":         user.Email,
		"password":      password,
		"signature":     signature,
		"business_name": user.Email, // Using email as business name as a fallback
		"timestamp":     timestamp,
	})
	if err != nil {
		return fmt.Errorf("failed to marshal request body: %w", err)
	}

	// Make the POST request
	resp, err := http.Post(endpoint, "application/json", bytes.NewBuffer(requestBody))
	if err != nil {
		return fmt.Errorf("failed to make wallet creation request: %w", err)
	}
	defer resp.Body.Close()

	// Read the response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	// Check if the request was successful
	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("wallet creation failed with status code %d: %s", resp.StatusCode, string(respBody))
	}

	// Parse the response
	var response struct {
		Status  int    `json:"status"`
		Message string `json:"message"`
		Data    struct {
			SessionID       string `json:"session_id"`
			CompanyID       string `json:"company_id"`
			Email           string `json:"email"`
			NwcString       string `json:"nwc_string"`
			NwcConnectionID string `json:"nwc_connection_id"`
		} `json:"data"`
	}

	if err := json.Unmarshal(respBody, &response); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	// Check if nwc_string is present
	if response.Data.NwcString == "" {
		return fmt.Errorf("empty NWC string received")
	}

	// Parse the wallet connect string
	parsedWallet, err := walletService.ParseWalletConnectString(response.Data.NwcString)
	if err != nil {
		return fmt.Errorf("failed to parse wallet connect string: %w", err)
	}

	// Create a default account for the user
	account := &Account{
		ID:        uuid.New(),
		UserID:    user.ID,
		Name:      "Default Account",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	createdAccount, err := accountRepository.Create(account)
	if err != nil {
		return fmt.Errorf("failed to create default account: %w", err)
	}

	// Create the wallet connection
	wallet := &WalletConnection{
		ID:          uuid.New(),
		UserID:      user.ID,
		AccountID:   createdAccount.ID,
		NostrPubkey: parsedWallet.NostrPubkey,
		NostrSecret: parsedWallet.NostrSecret,
		NostrRelay:  parsedWallet.NostrRelay,
		Active:      true,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	_, err = walletService.Create(wallet)
	if err != nil {
		return fmt.Errorf("failed to create wallet connection: %w", err)
	}

	return nil
}

func (s *UserService) Update(user *User) error {
	if user.Password != "" {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
		if err != nil {
			return err
		}
		user.Password = string(hashedPassword)
	}

	err := userRepository.Update(user)
	if err == nil {
		userCache.Set(user)
	}
	return err
}

func (s *UserService) Get(id uuid.UUID) (*User, error) {
	if cachedUser, found := userCache.Get(id); found && cachedUser != nil {
		return cachedUser, nil
	}

	user, err := userRepository.Get(id)
	if err == nil && user != nil {
		userCache.Set(user)
	}
	return user, err
}

func (s *UserService) Delete(id uuid.UUID) error {
	err := userRepository.Delete(id)
	if err == nil {
		userCache.cache.Delete(id)
	}
	return err
}

func (s *UserService) GetByEmail(email string) (*User, error) {
	user, err := userRepository.GetByEmail(email)
	if err == nil && user != nil {
		userCache.Set(user)
	}
	return user, err
}

func (h *UserHandler) Register(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Email           string `json:"email" validate:"required,email"`
		Password        string `json:"password" validate:"required,min=6"`
		ConfirmPassword string `json:"confirm_password" validate:"required,eqfield=Password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		JsonResponse(w, http.StatusBadRequest, "Invalid request", err.Error())
		return
	}

	if err := h.Validator.Struct(input); err != nil {
		JsonResponse(w, http.StatusBadRequest, "Invalid request", err.Error())
		return
	}

	user := &User{
		ID:        uuid.New(),
		Email:     input.Email,
		Password:  input.Password,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	createdUser, err := userService.Create(user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// After successfully creating the user, attempt to create a wallet
	err = userService.CreateWalletForUser(createdUser, input.Password)
	if err != nil {
		// Log the error but don't fail the registration if wallet creation fails
		// This way users can still register even if wallet creation has issues
		logger.Error("Failed to create wallet for new user", "error", err.Error(), "user_id", createdUser.ID)
	}

	JsonResponse(w, http.StatusCreated, "User created successfully", createdUser)
}

func (h *UserHandler) Login(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Email    string `json:"email" validate:"required,email"`
		Password string `json:"password" validate:"required"`
	}

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		JsonResponse(w, http.StatusBadRequest, "Invalid request", err.Error())
		return
	}

	if err := h.Validator.Struct(input); err != nil {
		JsonResponse(w, http.StatusBadRequest, "Invalid request", err.Error())
		return
	}
	user, err := userService.GetByEmail(input.Email)
	if err != nil || bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(input.Password)) != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	session := &Session{
		ID:           uuid.New(),
		UserID:       user.ID,
		SessionToken: uuid.NewString(),
		LoggedInAt:   time.Now(),
		Status:       "active",
	}

	newSession, err := sessionRepository.Create(session)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	JsonResponse(w, http.StatusCreated, "User logged in successfully", newSession)
}

func (h *UserHandler) Logout(w http.ResponseWriter, r *http.Request) {
	sessionIDStr := r.Header.Get("Session-ID")
	if sessionIDStr == "" {
		JsonResponse(w, http.StatusBadRequest, "No session token provided", nil)
		return
	}
	sessionID, err := uuid.Parse(sessionIDStr)
	if err != nil {
		JsonResponse(w, http.StatusBadRequest, "Invalid session token format", nil)
		return
	}

	session, err := sessionRepository.Get(sessionID)
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Failed to get session", err.Error())
		return
	}

	now := time.Now()
	session.Status = "inactive"
	session.LoggedOutAt = &now

	err = sessionRepository.Update(session)
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Failed to update session", err.Error())
		return
	}

	sessionCache.Invalidate(sessionID)

	JsonResponse(w, http.StatusOK, "User logged out successfully", nil)
}

func (h *UserHandler) Dashboard(w http.ResponseWriter, r *http.Request) {
	user, err := GetUserFromContext(r.Context())
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error retrieving user", err.Error())
		return
	}

	response := struct {
		ID          uuid.UUID  `json:"id"`
		Email       string     `json:"email"`
		LastLoginAt *time.Time `json:"last_login_at,omitempty"`
		CreatedAt   time.Time  `json:"created_at"`
		UpdatedAt   time.Time  `json:"updated_at"`
	}{
		ID:          user.ID,
		Email:       user.Email,
		LastLoginAt: user.LastLoginAt,
		CreatedAt:   user.CreatedAt,
		UpdatedAt:   user.UpdatedAt,
	}

	JsonResponse(w, http.StatusOK, "User dashboard data", response)
}
