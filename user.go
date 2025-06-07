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
	ID                     uuid.UUID  `db:"id" json:"id"`
	Email                  string     `db:"email" json:"email"`
	Password               string     `db:"password" json:"password"`
	TOTPSecret             *string    `db:"totp_secret" json:"totp_secret,omitempty"`
	EmailConfirmationToken *string    `db:"email_confirmation_token" json:"email_confirmation_token,omitempty"`
	EmailConfirmedAt       *time.Time `db:"email_confirmed_at" json:"email_confirmed_at,omitempty"`
	LastLoginAt            *time.Time `db:"last_login_at" json:"last_login_at,omitempty"`
	CreatedAt              time.Time  `db:"created_at" json:"created_at"`
	UpdatedAt              time.Time  `db:"updated_at" json:"updated_at"`
	DeletedAt              *time.Time `db:"deleted_at" json:"deleted_at,omitempty"`
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
	err := db.Get(user, "INSERT INTO users (id, email, password, totp_secret, email_confirmation_token, email_confirmed_at, last_login_at, created_at, updated_at, deleted_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING *", user.ID, user.Email, user.Password, user.TOTPSecret, user.EmailConfirmationToken, user.EmailConfirmedAt, user.LastLoginAt, user.CreatedAt, user.UpdatedAt, user.DeletedAt)
	return user, err
}

func (r *UserRepository) Update(user *User) error {
	_, err := db.Exec("UPDATE users SET email=$1, password=$2, totp_secret=$3, email_confirmation_token=$4, email_confirmed_at=$5, last_login_at=$6, updated_at=$7, deleted_at=$8 WHERE id=$9", user.Email, user.Password, user.TOTPSecret, user.EmailConfirmationToken, user.EmailConfirmedAt, user.LastLoginAt, user.UpdatedAt, user.DeletedAt, user.ID)
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

func (r *UserRepository) GetByConfirmationToken(token string) (*User, error) {
	user := &User{}
	err := db.Get(user, "SELECT * FROM users WHERE email_confirmation_token=$1 AND deleted_at IS NULL", token)
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

func (s *UserService) SendEmailConfirmation(user *User) error {
	// Skip if no notification service available
	if notificationService == nil {
		return fmt.Errorf("notification service not available")
	}

	// Get frontend URL from environment
	frontendURL := os.Getenv("FRONTEND_URL")
	if frontendURL == "" {
		return fmt.Errorf("FRONTEND_URL environment variable not set")
	}

	// Generate confirmation link
	confirmationLink := fmt.Sprintf("%s/confirm/%s/%s", frontendURL, user.ID.String(), *user.EmailConfirmationToken)

	// Get email adapter
	adapter, ok := notificationService.adapters[NotificationChannelEmail]
	if !ok {
		return fmt.Errorf("no email adapter available")
	}

	// Create plain text email content
	subject := "Confirm Your Email Address - Bitvora Commerce"
	textBody := fmt.Sprintf(`Hi there!

Welcome to Bitvora Commerce! Please confirm your email address to complete your registration.

Click the link below to confirm your email:
%s

If you did not create an account, you can safely ignore this email.

This confirmation link will expire in 24 hours.

Best regards,
The Bitvora Commerce Team`, confirmationLink)

	// Send plain text email (empty HTML body)
	err := adapter.Send(user.Email, subject, "", textBody)
	if err != nil {
		return fmt.Errorf("failed to send confirmation email: %w", err)
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

func (s *UserService) GetByConfirmationToken(token string) (*User, error) {
	user, err := userRepository.GetByConfirmationToken(token)
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

	// Generate email confirmation token
	confirmationToken := uuid.NewString()

	user := &User{
		ID:                     uuid.New(),
		Email:                  input.Email,
		Password:               input.Password,
		EmailConfirmationToken: &confirmationToken,
		EmailConfirmedAt:       nil, // Not confirmed yet
		CreatedAt:              time.Now(),
		UpdatedAt:              time.Now(),
	}
	createdUser, err := userService.Create(user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Send email confirmation
	err = userService.SendEmailConfirmation(createdUser)
	if err != nil {
		// Log the error but don't fail registration if email sending fails
		logger.Error("Failed to send confirmation email", "error", err.Error(), "user_id", createdUser.ID, "email", createdUser.Email)
	} else {
		logger.Info("Confirmation email sent successfully", "user_id", createdUser.ID, "email", createdUser.Email)
	}

	// After successfully creating the user, attempt to create a wallet
	err = userService.CreateWalletForUser(createdUser, input.Password)
	if err != nil {
		// Log the error but don't fail the registration if wallet creation fails
		// This way users can still register even if wallet creation has issues
		logger.Error("Failed to create wallet for new user", "error", err.Error(), "user_id", createdUser.ID)
	}

	// Return user data without sensitive information
	response := struct {
		ID        uuid.UUID `json:"id"`
		Email     string    `json:"email"`
		CreatedAt time.Time `json:"created_at"`
	}{
		ID:        createdUser.ID,
		Email:     createdUser.Email,
		CreatedAt: createdUser.CreatedAt,
	}

	JsonResponse(w, http.StatusCreated, "User created successfully. Please check your email to confirm your account.", response)
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

	// Check if email is confirmed
	if user.EmailConfirmedAt == nil {
		JsonResponse(w, http.StatusPreconditionFailed, "Email not confirmed", "Please check your email and click the confirmation link before logging in.")
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

func (h *UserHandler) ConfirmEmail(w http.ResponseWriter, r *http.Request) {
	var input struct {
		UserID            string `json:"user_id" validate:"required"`
		ConfirmationToken string `json:"confirmation_token" validate:"required"`
	}

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		JsonResponse(w, http.StatusBadRequest, "Invalid request", err.Error())
		return
	}

	if err := h.Validator.Struct(input); err != nil {
		JsonResponse(w, http.StatusBadRequest, "Invalid request", err.Error())
		return
	}

	userID, err := uuid.Parse(input.UserID)
	if err != nil {
		JsonResponse(w, http.StatusBadRequest, "Invalid user ID format", err.Error())
		return
	}

	// Get user by confirmation token to verify it matches
	user, err := userService.GetByConfirmationToken(input.ConfirmationToken)
	if err != nil {
		JsonResponse(w, http.StatusBadRequest, "Invalid or expired confirmation token", err.Error())
		return
	}

	// Verify the user ID matches
	if user.ID != userID {
		JsonResponse(w, http.StatusBadRequest, "Invalid confirmation token for this user", nil)
		return
	}

	// Check if already confirmed
	if user.EmailConfirmedAt != nil {
		JsonResponse(w, http.StatusBadRequest, "Email already confirmed", nil)
		return
	}

	// Confirm the email
	now := time.Now()
	user.EmailConfirmedAt = &now
	user.EmailConfirmationToken = nil // Clear the token
	user.UpdatedAt = now

	err = userService.Update(user)
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Failed to confirm email", err.Error())
		return
	}

	// Create a session for automatic login
	session := &Session{
		ID:           uuid.New(),
		UserID:       user.ID,
		SessionToken: uuid.NewString(),
		LoggedInAt:   time.Now(),
		Status:       "active",
	}

	newSession, err := sessionRepository.Create(session)
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Email confirmed but failed to create session", err.Error())
		return
	}

	JsonResponse(w, http.StatusOK, "Email confirmed successfully", newSession)
}

func (h *UserHandler) ResendConfirmation(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Email string `json:"email" validate:"required,email"`
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
	if err != nil {
		// Don't reveal if email exists or not for security
		JsonResponse(w, http.StatusOK, "If the email exists and is not confirmed, a new confirmation email will be sent", nil)
		return
	}

	// Check if already confirmed
	if user.EmailConfirmedAt != nil {
		JsonResponse(w, http.StatusBadRequest, "Email is already confirmed", nil)
		return
	}

	// Generate new confirmation token
	newToken := uuid.NewString()
	user.EmailConfirmationToken = &newToken
	user.UpdatedAt = time.Now()

	err = userService.Update(user)
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Failed to update user", err.Error())
		return
	}

	// Send new confirmation email
	err = userService.SendEmailConfirmation(user)
	if err != nil {
		logger.Error("Failed to resend confirmation email", "error", err.Error(), "user_id", user.ID, "email", user.Email)
		JsonResponse(w, http.StatusInternalServerError, "Failed to send confirmation email", err.Error())
		return
	}

	logger.Info("Confirmation email resent successfully", "user_id", user.ID, "email", user.Email)
	JsonResponse(w, http.StatusOK, "Confirmation email sent successfully", nil)
}
