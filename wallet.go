package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip04"
	"golang.org/x/crypto/chacha20poly1305"
)

var (
	encryptionKey []byte
)

func init() {
	keyStr := os.Getenv("CHACHA_ENCRYPTION_KEY")
	if keyStr == "" {
		keyStr = "defaultKey12345678901234567890123456"
	}

	encryptionKey = []byte(keyStr)
	if len(encryptionKey) != chacha20poly1305.KeySize {
		newKey := make([]byte, chacha20poly1305.KeySize)
		copy(newKey, encryptionKey)
		encryptionKey = newKey
	}
}

func encrypt(plaintext string) (string, error) {
	aead, err := chacha20poly1305.New(encryptionKey)
	if err != nil {
		return "", fmt.Errorf("failed to create AEAD: %w", err)
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := aead.Seal(nil, nonce, []byte(plaintext), nil)

	combined := make([]byte, len(nonce)+len(ciphertext))
	copy(combined, nonce)
	copy(combined[len(nonce):], ciphertext)

	encoded := base64.StdEncoding.EncodeToString(combined)
	return encoded, nil
}

func decrypt(encoded string) (string, error) {
	combined, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64 string: %w", err)
	}

	aead, err := chacha20poly1305.New(encryptionKey)
	if err != nil {
		return "", fmt.Errorf("failed to create AEAD: %w", err)
	}

	if len(combined) < aead.NonceSize() {
		return "", fmt.Errorf("ciphertext too short, expected at least %d bytes, got %d", aead.NonceSize(), len(combined))
	}
	nonce := combined[:aead.NonceSize()]
	ciphertext := combined[aead.NonceSize():]

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt content: %w", err)
	}

	return string(plaintext), nil
}

type WalletConnection struct {
	ID           uuid.UUID       `db:"id" json:"id"`
	UserID       uuid.UUID       `db:"user_id" json:"user_id"`
	AccountID    uuid.UUID       `db:"account_id" json:"account_id"`
	NostrPubkey  string          `db:"nostr_pubkey" json:"nostr_pubkey"`
	NostrSecret  string          `db:"nostr_secret" json:"nostr_secret"`
	NostrRelay   string          `db:"nostr_relay" json:"nostr_relay"`
	SecretPubkey string          `db:"-" json:"-"`
	Active       bool            `db:"active" json:"active"`
	CreatedAt    time.Time       `db:"created_at" json:"created_at"`
	UpdatedAt    time.Time       `db:"updated_at" json:"updated_at"`
	ExpiredAt    *time.Time      `db:"expired_at" json:"expired_at,omitempty"`
	DeletedAt    *time.Time      `db:"deleted_at" json:"deleted_at,omitempty"`
	Methods      json.RawMessage `db:"methods" json:"methods"`
}

type WalletCache struct {
	cache sync.Map
}

func (c *WalletCache) Get(id uuid.UUID) (*WalletConnection, bool) {
	value, ok := c.cache.Load(id)
	if !ok {
		return nil, false
	}
	wallet, ok := value.(*WalletConnection)
	return wallet, ok
}

func (c *WalletCache) Set(wallet *WalletConnection) {
	if wallet != nil {
		c.cache.Store(wallet.ID, wallet)
	}
}

type WalletRepository struct{}
type WalletService struct{}

var walletRepository = &WalletRepository{}
var walletCache = &WalletCache{}
var walletService = &WalletService{}

// NWCRequest represents a Nostr Wallet Connect request
type NWCRequest struct {
	Method string      `json:"method"`
	Params interface{} `json:"params,omitempty"`
}

// NWCResponse represents a Nostr Wallet Connect response
type NWCResponse struct {
	ResultType string          `json:"result_type"`
	Error      *NWCError       `json:"error,omitempty"`
	Result     json.RawMessage `json:"result,omitempty"`
}

// NWCError represents an error in NWC response
type NWCError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// sendNWCRequest sends a request to a wallet using request-specific subscription
func sendNWCRequest(ctx context.Context, wallet *WalletConnection, method string, params interface{}, timeout time.Duration) (json.RawMessage, error) {
	logger.Debug("Preparing NWC request", "method", method, "wallet_id", wallet.ID, "relay", wallet.NostrRelay)

	// Prepare the request
	req := NWCRequest{
		Method: method,
		Params: params,
	}

	reqBytes, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Get the client secret key (wallet secret)
	clientSecretKey := wallet.NostrSecret
	if len(clientSecretKey) != 64 && len(clientSecretKey) != 32 {
		clientSecretKey, err = decrypt(wallet.NostrSecret)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt wallet secret: %w", err)
		}
	}

	// Derive client public key
	clientPubKey, err := nostr.GetPublicKey(clientSecretKey)
	if err != nil {
		return nil, fmt.Errorf("failed to derive client public key: %w", err)
	}

	// Compute shared secret for encryption - try different approaches for compatibility
	var sharedSecret []byte

	// Approach 1: Standard order (wallet pubkey, client secret)
	sharedSecret, err = nip04.ComputeSharedSecret(wallet.NostrPubkey, clientSecretKey)
	if err != nil {
		// Approach 2: Try with "02" prefix
		walletPubKeyWithPrefix := "02" + wallet.NostrPubkey
		sharedSecret, err = nip04.ComputeSharedSecret(walletPubKeyWithPrefix, clientSecretKey)
		if err != nil {
			return nil, fmt.Errorf("failed to compute shared secret: %w", err)
		}
	}

	// Encrypt the request
	encryptedContent, err := nip04.Encrypt(string(reqBytes), sharedSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt request: %w", err)
	}

	// Create the event
	event := nostr.Event{
		Kind:      nostr.KindNWCWalletRequest,
		PubKey:    clientPubKey,
		CreatedAt: nostr.Now(),
		Content:   encryptedContent,
		Tags: nostr.Tags{
			nostr.Tag{"p", wallet.NostrPubkey},
		},
	}

	// Sign the event
	event.Sign(clientSecretKey)

	// Validate signature
	if ok, err := event.CheckSignature(); !ok || err != nil {
		return nil, fmt.Errorf("event signature validation failed: %v, %w", ok, err)
	}

	// Create a simple pool for this request
	pool := nostr.NewSimplePool(ctx)

	// Set up response subscription BEFORE sending request
	responseFilters := nostr.Filter{
		Kinds: []int{nostr.KindNWCWalletResponse},
		Tags: nostr.TagMap{
			"e": []string{event.ID},     // Filter by our request event ID
			"p": []string{clientPubKey}, // Filter by our client pubkey
		},
		Limit: 1, // Only need one response
	}

	responseSub := pool.SubscribeMany(ctx, []string{wallet.NostrRelay}, responseFilters)

	// Set up response channel
	responseChan := make(chan nostr.Event, 1)
	go func() {
		defer close(responseChan)
		for evt := range responseSub {
			if evt.Event != nil {
				logger.Debug("Received response event", "response_event_id", evt.Event.ID, "request_event_id", event.ID)
				responseChan <- *evt.Event
				break // Only need one response
			}
		}
	}()

	// Publish the request
	status := pool.PublishMany(ctx, []string{wallet.NostrRelay}, event)
	if stat := <-status; stat.Error != nil {
		return nil, fmt.Errorf("failed to publish event to %s: %w", wallet.NostrRelay, stat.Error)
	}

	logger.Info("Sent NWC request", "method", method, "event_id", event.ID, "relay", wallet.NostrRelay)

	// Wait for response with timeout
	timeoutTimer := time.NewTimer(timeout)
	defer timeoutTimer.Stop()

	select {
	case resp := <-responseChan:
		logger.Debug("Received response", "response_event_id", resp.ID)

		// Decrypt the response
		decrypted, err := decryptNWCResponse(resp, clientSecretKey, wallet.NostrPubkey)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt response: %w", err)
		}

		// Parse the response
		var nwcResp NWCResponse
		if err := json.Unmarshal([]byte(decrypted), &nwcResp); err != nil {
			return nil, fmt.Errorf("failed to parse NWC response: %w", err)
		}

		// Check for errors
		if nwcResp.Error != nil {
			return nil, fmt.Errorf("wallet error: %s - %s", nwcResp.Error.Code, nwcResp.Error.Message)
		}

		return nwcResp.Result, nil

	case <-timeoutTimer.C:
		return nil, fmt.Errorf("request timed out after %v", timeout)
	}
}

// decryptNWCResponse decrypts a response event content using multiple approaches for compatibility
func decryptNWCResponse(event nostr.Event, clientSecKey, walletPubKey string) (string, error) {
	logger.Debug("Decrypting response", "event_id", event.ID, "event_pubkey", event.PubKey)

	// Use the actual response pubkey for decryption
	responsePubKey := event.PubKey
	if event.PubKey != walletPubKey {
		logger.Debug("Response pubkey differs from wallet pubkey", "expected", walletPubKey, "actual", event.PubKey)
	}

	// Try multiple approaches for shared secret computation
	var sharedSecret []byte
	var err error

	// Approach 1: Standard order (response pubkey, client secret) - most common
	sharedSecret, err = nip04.ComputeSharedSecret(responsePubKey, clientSecKey)
	if err == nil {
		if decrypted, decErr := nip04.Decrypt(event.Content, sharedSecret); decErr == nil {
			return decrypted, nil
		}
	}

	// Approach 2: Try with "02" prefix
	responsePubKeyWithPrefix := "02" + responsePubKey
	sharedSecret, err = nip04.ComputeSharedSecret(responsePubKeyWithPrefix, clientSecKey)
	if err == nil {
		if decrypted, decErr := nip04.Decrypt(event.Content, sharedSecret); decErr == nil {
			return decrypted, nil
		}
	}

	// Approach 3: Try the original wallet pubkey instead of response pubkey
	sharedSecret, err = nip04.ComputeSharedSecret(walletPubKey, clientSecKey)
	if err == nil {
		if decrypted, decErr := nip04.Decrypt(event.Content, sharedSecret); decErr == nil {
			return decrypted, nil
		}
	}

	// Approach 4: Try original wallet pubkey with prefix
	walletPubKeyWithPrefix := "02" + walletPubKey
	sharedSecret, err = nip04.ComputeSharedSecret(walletPubKeyWithPrefix, clientSecKey)
	if err == nil {
		if decrypted, decErr := nip04.Decrypt(event.Content, sharedSecret); decErr == nil {
			return decrypted, nil
		}
	}

	return "", fmt.Errorf("failed to decrypt content using any approach")
}

type ResponsePromise struct {
	Response chan []byte
	Timeout  *time.Timer
	UserData interface{}
}

// NewWalletListener is no longer needed with request-specific connections

func (r *WalletRepository) Create(wallet *WalletConnection) (*WalletConnection, error) {
	originalSecret := wallet.NostrSecret

	encryptedSecret, err := encrypt(wallet.NostrSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt nostr secret: %w", err)
	}

	wallet.NostrSecret = encryptedSecret

	err = db.Get(wallet, `
		INSERT INTO wallet_connections (
			id, user_id, account_id, nostr_pubkey, nostr_secret, nostr_relay, active,
			created_at, updated_at, expired_at, deleted_at, methods
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12
		) RETURNING *`,
		wallet.ID, wallet.UserID, wallet.AccountID, wallet.NostrPubkey, wallet.NostrSecret, wallet.NostrRelay, wallet.Active,
		wallet.CreatedAt, wallet.UpdatedAt, wallet.ExpiredAt, wallet.DeletedAt, wallet.Methods)

	if err == nil {
		wallet.NostrSecret = originalSecret
	}

	return wallet, err
}

func (r *WalletRepository) Get(id uuid.UUID) (*WalletConnection, error) {
	wallet := &WalletConnection{}
	err := db.Get(wallet, "SELECT * FROM wallet_connections WHERE id=$1 AND deleted_at IS NULL", id)
	if err != nil {
		return nil, err
	}

	decryptedSecret, err := decrypt(wallet.NostrSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt nostr secret: %w", err)
	}
	wallet.NostrSecret = decryptedSecret

	return wallet, nil
}

func (r *WalletRepository) GetByUser(userID uuid.UUID) ([]*WalletConnection, error) {
	wallets := []*WalletConnection{}
	err := db.Select(&wallets, "SELECT * FROM wallet_connections WHERE user_id=$1 AND deleted_at IS NULL ORDER BY created_at DESC", userID)
	if err != nil {
		return nil, err
	}

	for _, wallet := range wallets {
		decryptedSecret, err := decrypt(wallet.NostrSecret)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt nostr secret: %w", err)
		}
		wallet.NostrSecret = decryptedSecret
	}

	return wallets, nil
}

func (r *WalletRepository) GetByAccount(accountID uuid.UUID) ([]*WalletConnection, error) {
	wallets := []*WalletConnection{}
	err := db.Select(&wallets, "SELECT * FROM wallet_connections WHERE account_id=$1 AND deleted_at IS NULL ORDER BY created_at DESC", accountID)
	if err != nil {
		return nil, err
	}

	for _, wallet := range wallets {
		decryptedSecret, err := decrypt(wallet.NostrSecret)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt nostr secret: %w", err)
		}
		wallet.NostrSecret = decryptedSecret
	}

	return wallets, nil
}

func (r *WalletRepository) GetActiveWalletConnections() ([]*WalletConnection, error) {
	wallets := []*WalletConnection{}
	err := db.Select(&wallets, "SELECT * FROM wallet_connections WHERE active = true AND deleted_at IS NULL ORDER BY created_at DESC")
	if err != nil {
		return nil, err
	}

	return wallets, nil
}

func (r *WalletRepository) Delete(id uuid.UUID) error {
	_, err := db.Exec("UPDATE wallet_connections SET deleted_at=$1 WHERE id=$2", time.Now(), id)
	return err
}

func (r *WalletRepository) DeactivateOtherWallets(userID, accountID uuid.UUID) error {
	_, err := db.Exec(`
		UPDATE wallet_connections 
		SET active = false 
		WHERE user_id = $1 AND account_id = $2 AND active = true`,
		userID, accountID)
	return err
}

func (s *WalletService) Create(wallet *WalletConnection) (*WalletConnection, error) {
	wallet.Active = true
	wallet.CreatedAt = time.Now()
	wallet.UpdatedAt = time.Now()

	plainTextSecret := wallet.NostrSecret

	derivedPubkey, err := nostr.GetPublicKey(plainTextSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to derive public key from secret: %w", err)
	}
	wallet.SecretPubkey = derivedPubkey

	info, err := s.GetInfo(wallet.NostrPubkey, wallet.NostrSecret, wallet.NostrRelay)
	if err != nil {
		return nil, fmt.Errorf("failed to get info: %w", err)
	}

	var response struct {
		ResultType string `json:"result_type"`
		Result     struct {
			Methods []string `json:"methods"`
		} `json:"result"`
	}

	if err := json.Unmarshal(info, &response); err != nil {
		return nil, fmt.Errorf("failed to parse info response: %w", err)
	}

	// Save the methods to the wallet
	methodsJson, err := json.Marshal(response.Result.Methods) // Save methods to the wallet
	if err != nil {
		return nil, fmt.Errorf("failed to marshal methods: %w", err)
	}

	wallet.Methods = methodsJson

	logger.Info("Wallet methods", "methods", response.Result.Methods)

	if !slices.Contains(response.Result.Methods, "get_info") {
		return nil, fmt.Errorf("wallet does not support get_info")
	}

	if !slices.Contains(response.Result.Methods, "make_invoice") {
		return nil, fmt.Errorf("wallet does not support make_invoice")
	}

	if !slices.Contains(response.Result.Methods, "list_transactions") {
		return nil, fmt.Errorf("wallet does not support list_transactions")
	}

	err = walletRepository.DeactivateOtherWallets(wallet.UserID, wallet.AccountID)
	if err != nil {
		return nil, err
	}

	createdWallet, err := walletRepository.Create(wallet)
	if err == nil && createdWallet != nil {
		createdWallet.NostrSecret = plainTextSecret
		walletCache.Set(createdWallet)

		// Wallet is ready to use immediately - no need for listener
	}
	return createdWallet, err
}

func (s *WalletService) Get(id uuid.UUID) (*WalletConnection, error) {
	if cachedWallet, found := walletCache.Get(id); found && cachedWallet != nil {
		return cachedWallet, nil
	}

	wallet, err := walletRepository.Get(id)
	if err == nil && wallet != nil {
		walletCache.Set(wallet)
	}
	return wallet, err
}

func (s *WalletService) GetByUser(userID uuid.UUID) ([]*WalletConnection, error) {
	return walletRepository.GetByUser(userID)
}

func (s *WalletService) GetActiveWalletByUser(userID uuid.UUID) (*WalletConnection, error) {
	wallets, err := s.GetByUser(userID)
	if err != nil {
		return nil, err
	}

	for _, wallet := range wallets {
		if wallet.Active {
			return wallet, nil
		}
	}

	return nil, fmt.Errorf("no active wallet found")
}

func (s *WalletService) GetActiveWalletByAccount(accountID uuid.UUID) (*WalletConnection, error) {
	wallets, err := s.GetByAccount(accountID)
	if err != nil {
		return nil, err
	}

	for _, wallet := range wallets {
		if wallet.Active {
			return wallet, nil
		}
	}

	return nil, fmt.Errorf("no active wallet found")
}

func (s *WalletService) GetByAccount(accountID uuid.UUID) ([]*WalletConnection, error) {
	return walletRepository.GetByAccount(accountID)
}

func (s *WalletService) Delete(id uuid.UUID) error {
	err := walletRepository.Delete(id)
	if err == nil {
		walletCache.cache.Delete(id)
	}
	return err
}

type WalletHandler struct {
	Validator *validator.Validate
}

var walletHandler = &WalletHandler{
	Validator: validator.New(),
}

func (h *WalletHandler) Create(w http.ResponseWriter, r *http.Request) {
	var input struct {
		AccountID     uuid.UUID `json:"account_id" validate:"required"`
		WalletConnect string    `json:"wallet_connect" validate:"required"`
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
		JsonResponse(w, http.StatusForbidden, "You are not authorized to use this account", nil)
		return
	}

	parsedWallet, err := parseWalletConnectString(input.WalletConnect)
	if err != nil {
		JsonResponse(w, http.StatusBadRequest, "Invalid wallet connection string", err.Error())
		return
	}

	wallet := &WalletConnection{
		ID:          uuid.New(),
		UserID:      user.ID,
		AccountID:   input.AccountID,
		NostrPubkey: parsedWallet.NostrPubkey,
		NostrSecret: parsedWallet.NostrSecret,
		NostrRelay:  parsedWallet.NostrRelay,
		Active:      true,
	}

	createdWallet, err := walletService.Create(wallet)
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error connecting wallet", err.Error())
		return
	}

	JsonResponse(w, http.StatusCreated, "Wallet connected successfully", createdWallet)
}

func parseWalletConnectString(walletConnect string) (*WalletConnection, error) {

	if !strings.HasPrefix(walletConnect, "nostr+walletconnect://") {
		return nil, fmt.Errorf("invalid format")
	}
	walletConnect = strings.TrimPrefix(walletConnect, "nostr+walletconnect://")

	parts := strings.Split(walletConnect, "?")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid format")
	}

	walletID := parts[0]

	params := parts[1]
	paramMap := make(map[string]string)
	for _, param := range strings.Split(params, "&") {
		kv := strings.SplitN(param, "=", 2)
		if len(kv) == 2 {
			paramMap[kv[0]] = kv[1]
		}
	}

	relay, err := url.QueryUnescape(paramMap["relay"])
	if err != nil {
		return nil, fmt.Errorf("failed to decode relay URL: %w", err)
	}

	secret := paramMap["secret"]

	return &WalletConnection{
		NostrPubkey: walletID,
		NostrRelay:  relay,
		NostrSecret: secret,
	}, nil
}

func (h *WalletHandler) MakeInvoice(w http.ResponseWriter, r *http.Request) {
	user, err := GetUserFromContext(r.Context())
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error retrieving user", err.Error())
		return
	}

	var input struct {
		AccountID uuid.UUID `json:"account_id"`
		Amount    int64     `json:"amount"`
		Desc      string    `json:"desc"`
		Expiry    int64     `json:"expiry"`
	}

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		JsonResponse(w, http.StatusBadRequest, "Invalid request", err.Error())
		return
	}

	wallet, err := walletService.GetActiveWalletByAccount(input.AccountID)
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error retrieving wallet connections", err.Error())
		return
	}

	if wallet.UserID != user.ID {
		JsonResponse(w, http.StatusForbidden, "You are not authorized to create an invoice for this account", nil)
		return
	}

	invoice, err := walletService.MakeInvoice(wallet.ID, input.Amount, input.Desc, input.Expiry)
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error creating invoice", err.Error())
		return
	}

	JsonResponse(w, http.StatusOK, "Invoice created successfully", invoice)
}

func (h *WalletHandler) Get(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		JsonResponse(w, http.StatusBadRequest, "Invalid wallet connection ID", err.Error())
		return
	}

	user, err := GetUserFromContext(r.Context())
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error retrieving user", err.Error())
		return
	}

	wallet, err := walletService.Get(id)
	if err != nil {
		JsonResponse(w, http.StatusNotFound, "Wallet connection not found", err.Error())
		return
	}

	if wallet.UserID != user.ID {
		JsonResponse(w, http.StatusForbidden, "You are not authorized to view this wallet connection", nil)
		return
	}

	JsonResponse(w, http.StatusOK, "Wallet connection retrieved successfully", wallet)
}

func (h *WalletHandler) GetAll(w http.ResponseWriter, r *http.Request) {
	user, err := GetUserFromContext(r.Context())
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error retrieving user", err.Error())
		return
	}

	wallets, err := walletService.GetByUser(user.ID)
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error retrieving wallet connections", err.Error())
		return
	}

	JsonResponse(w, http.StatusOK, "Wallet connections retrieved successfully", wallets)
}

func (h *WalletHandler) GetByAccount(w http.ResponseWriter, r *http.Request) {
	accountIDStr := chi.URLParam(r, "accountId")
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
		JsonResponse(w, http.StatusForbidden, "You are not authorized to view wallet connections for this account", nil)
		return
	}

	wallets, err := walletService.GetByAccount(accountID)
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error retrieving wallet connections", err.Error())
		return
	}

	JsonResponse(w, http.StatusOK, "Wallet connections retrieved successfully", wallets)
}

func (h *WalletHandler) Delete(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		JsonResponse(w, http.StatusBadRequest, "Invalid wallet connection ID", err.Error())
		return
	}

	user, err := GetUserFromContext(r.Context())
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error retrieving user", err.Error())
		return
	}

	wallet, err := walletService.Get(id)
	if err != nil {
		JsonResponse(w, http.StatusNotFound, "Wallet connection not found", err.Error())
		return
	}

	if wallet.UserID != user.ID {
		JsonResponse(w, http.StatusForbidden, "You are not authorized to delete this wallet connection", nil)
		return
	}

	err = walletService.Delete(id)
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error deleting wallet connection", err.Error())
		return
	}

	JsonResponse(w, http.StatusOK, "Wallet connection deleted successfully", nil)
}

func (h *WalletHandler) GetBalance(w http.ResponseWriter, r *http.Request) {
	user, err := GetUserFromContext(r.Context())
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error retrieving user", err.Error())
		return
	}

	accountIDStr := r.URL.Query().Get("account_id")
	if accountIDStr == "" {
		JsonResponse(w, http.StatusBadRequest, "Missing account_id parameter", nil)
		return
	}

	accountID, err := uuid.Parse(accountIDStr)
	if err != nil {
		JsonResponse(w, http.StatusBadRequest, "Invalid account_id parameter", err.Error())
		return
	}

	account, err := accountService.Get(accountID)
	if err != nil {
		JsonResponse(w, http.StatusNotFound, "Account not found", err.Error())
		return
	}

	if account.UserID != user.ID {
		JsonResponse(w, http.StatusForbidden, "You are not authorized to view balance for this account", nil)
		return
	}

	wallet, err := walletService.GetActiveWalletByAccount(accountID)
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error retrieving active wallet", err.Error())
		return
	}

	balanceMsats, err := walletService.GetBalance(wallet.ID)
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error getting wallet balance", err.Error())
		return
	}

	// Convert millisatoshis to satoshis
	balanceSats := balanceMsats / 1000

	response := map[string]interface{}{
		"balance_msats": balanceMsats,
		"balance_sats":  balanceSats,
		"wallet_id":     wallet.ID,
		"account_id":    accountID,
	}

	JsonResponse(w, http.StatusOK, "Wallet balance retrieved successfully", response)
}

func (h *WalletHandler) GetTransactions(w http.ResponseWriter, r *http.Request) {
	user, err := GetUserFromContext(r.Context())
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error retrieving user", err.Error())
		return
	}

	accountIDStr := r.URL.Query().Get("account_id")
	if accountIDStr == "" {
		JsonResponse(w, http.StatusBadRequest, "Missing account_id parameter", nil)
		return
	}

	accountID, err := uuid.Parse(accountIDStr)
	if err != nil {
		JsonResponse(w, http.StatusBadRequest, "Invalid account_id parameter", err.Error())
		return
	}

	account, err := accountService.Get(accountID)
	if err != nil {
		JsonResponse(w, http.StatusNotFound, "Account not found", err.Error())
		return
	}

	if account.UserID != user.ID {
		JsonResponse(w, http.StatusForbidden, "You are not authorized to view transactions for this account", nil)
		return
	}

	wallet, err := walletService.GetActiveWalletByAccount(accountID)
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error retrieving active wallet", err.Error())
		return
	}

	// Parse query parameters for filtering transactions
	var from, until int64
	var limit, offset int
	var unpaid bool
	var txType string

	// Parse 'from' parameter (timestamp)
	if fromStr := r.URL.Query().Get("from"); fromStr != "" {
		if fromVal, err := strconv.ParseInt(fromStr, 10, 64); err == nil {
			from = fromVal
		}
	}

	// Parse 'until' parameter (timestamp)
	if untilStr := r.URL.Query().Get("until"); untilStr != "" {
		if untilVal, err := strconv.ParseInt(untilStr, 10, 64); err == nil {
			until = untilVal
		}
	}

	// Parse 'limit' parameter
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if limitVal, err := strconv.Atoi(limitStr); err == nil && limitVal > 0 {
			limit = limitVal
		}
	}

	// Parse 'offset' parameter
	if offsetStr := r.URL.Query().Get("offset"); offsetStr != "" {
		if offsetVal, err := strconv.Atoi(offsetStr); err == nil && offsetVal >= 0 {
			offset = offsetVal
		}
	}

	// Parse 'unpaid' parameter
	if unpaidStr := r.URL.Query().Get("unpaid"); unpaidStr != "" {
		unpaid, _ = strconv.ParseBool(unpaidStr)
	}

	// Parse 'type' parameter
	txType = r.URL.Query().Get("type")

	// Call the wallet service to get transactions
	transactionsData, err := walletService.ListTransactions(wallet.ID, from, until, limit, offset, unpaid, txType)
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error retrieving wallet transactions", err.Error())
		return
	}

	// Parse the response to return as JSON
	var result interface{}
	if err := json.Unmarshal(transactionsData, &result); err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error parsing transaction data", err.Error())
		return
	}

	JsonResponse(w, http.StatusOK, "Wallet transactions retrieved successfully", result)
}

func (h *WalletHandler) Withdraw(w http.ResponseWriter, r *http.Request) {
	var input struct {
		AccountID uuid.UUID `json:"account_id" validate:"required"`
		Recipient string    `json:"recipient" validate:"required"`
		Amount    int64     `json:"amount" validate:"required,min=1"`
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
		JsonResponse(w, http.StatusForbidden, "You are not authorized to withdraw from this account", nil)
		return
	}

	wallet, err := walletService.GetActiveWalletByAccount(input.AccountID)
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error retrieving active wallet", err.Error())
		return
	}

	// Check wallet balance before attempting payment
	balanceMsats, err := walletService.GetBalance(wallet.ID)
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error checking wallet balance", err.Error())
		return
	}

	// Convert input amount (sats) to millisatoshis for comparison
	requiredMsats := input.Amount * 1000

	if balanceMsats < requiredMsats {
		response := map[string]interface{}{
			"available_balance_sats": balanceMsats / 1000,
			"required_amount_sats":   input.Amount,
			"shortage_sats":          (requiredMsats - balanceMsats) / 1000,
		}
		JsonResponse(w, http.StatusBadRequest, "Insufficient wallet balance", response)
		return
	}

	// Determine recipient type by parsing the string
	recipientType := determineRecipientType(input.Recipient)

	switch recipientType {
	case "lightning_invoice":
		// Pay lightning invoice using NWC
		response, err := walletService.PayInvoiceWithResponse(wallet.ID, input.Recipient)
		if err != nil {
			JsonResponse(w, http.StatusInternalServerError, "Error paying lightning invoice", err.Error())
			return
		}

		JsonResponse(w, http.StatusCreated, "Payment sent successfully", response)

	case "lightning_address":
		// Pay lightning address using existing wallet functionality
		response, err := walletService.PayLightningAddress(wallet.ID, input.Recipient, input.Amount)
		if err != nil {
			JsonResponse(w, http.StatusInternalServerError, "Error paying lightning address", err.Error())
			return
		}

		JsonResponse(w, http.StatusCreated, "Payment sent successfully", response)

	case "bitcoin_address":
		// TODO: Implement on-chain bitcoin payment
		// 1. Validate bitcoin address format
		// 2. Create on-chain transaction using wallet's make_chain_transaction method
		// 3. Broadcast transaction
		JsonResponse(w, http.StatusNotImplemented, "Bitcoin address payments not yet implemented", nil)

	default:
		JsonResponse(w, http.StatusBadRequest, "Invalid recipient format", "Recipient must be a lightning invoice, lightning address, or bitcoin address")
	}
}

// determineRecipientType analyzes the recipient string to determine its type
func determineRecipientType(recipient string) string {
	recipient = strings.TrimSpace(strings.ToLower(recipient))

	// Lightning invoice: starts with lnbc (mainnet) or lntb (testnet)
	if strings.HasPrefix(recipient, "lnbc") || strings.HasPrefix(recipient, "lntb") {
		return "lightning_invoice"
	}

	// Lightning address: email-like format (handle@domain.tld)
	if strings.Contains(recipient, "@") && strings.Contains(recipient, ".") {
		// Basic validation for email-like format
		parts := strings.Split(recipient, "@")
		if len(parts) == 2 && len(parts[0]) > 0 && len(parts[1]) > 0 {
			return "lightning_address"
		}
	}

	// Bitcoin addresses can be:
	// - Legacy (P2PKH): starts with 1, length 26-35
	// - Script (P2SH): starts with 3, length 26-35
	// - Bech32 (native segwit): starts with bc1, length 42 for P2WPKH or 62 for P2WSH
	// - Taproot: starts with bc1p, length 62

	originalRecipient := strings.TrimSpace(recipient) // Keep original case for address validation

	// Legacy address (P2PKH)
	if strings.HasPrefix(originalRecipient, "1") && len(originalRecipient) >= 26 && len(originalRecipient) <= 35 {
		return "bitcoin_address"
	}

	// Script address (P2SH)
	if strings.HasPrefix(originalRecipient, "3") && len(originalRecipient) >= 26 && len(originalRecipient) <= 35 {
		return "bitcoin_address"
	}

	// Bech32 segwit address
	if strings.HasPrefix(originalRecipient, "bc1") {
		if len(originalRecipient) == 42 || len(originalRecipient) == 62 {
			return "bitcoin_address"
		}
	}

	return "unknown"
}

func (s *WalletService) PublishEvent(walletID uuid.UUID, kind int, content string, tags nostr.Tags) error {
	wallet, err := s.Get(walletID)
	if err != nil {
		return err
	}

	walletPrivateKey, err := decrypt(wallet.NostrSecret)
	if err != nil {
		return fmt.Errorf("failed to decrypt wallet secret: %w", err)
	}

	event := nostr.Event{
		Kind:      kind,
		PubKey:    wallet.NostrPubkey,
		CreatedAt: nostr.Now(),
		Content:   content,
		Tags:      tags,
	}

	event.Sign(walletPrivateKey)

	ctx := context.Background()
	pool := nostr.NewSimplePool(ctx)
	pool.PublishMany(ctx, []string{wallet.NostrRelay}, event)

	return nil
}

func (s *WalletService) PayInvoice(walletID uuid.UUID, invoice string) error {
	wallet, err := s.Get(walletID)
	if err != nil {
		return err
	}

	params := map[string]interface{}{
		"invoice": invoice,
	}

	ctx := context.Background()
	_, err = sendNWCRequest(ctx, wallet, "pay_invoice", params, 30*time.Second)
	return err
}

// PayInvoiceWithResponse pays a lightning invoice and returns the full response data including preimage
func (s *WalletService) PayInvoiceWithResponse(walletID uuid.UUID, invoice string) (map[string]interface{}, error) {
	wallet, err := s.Get(walletID)
	if err != nil {
		return nil, err
	}

	logger.Info("Paying invoice", "wallet_id", walletID, "invoice", invoice)

	params := map[string]interface{}{
		"invoice": invoice,
	}

	ctx := context.Background()
	result, err := sendNWCRequest(ctx, wallet, "pay_invoice", params, 30*time.Second)
	if err != nil {
		return nil, err
	}

	// Parse the result
	var payResult struct {
		Preimage string `json:"preimage"`
		FeesPaid int64  `json:"fees_paid"`
	}

	if err := json.Unmarshal(result, &payResult); err != nil {
		return nil, fmt.Errorf("failed to parse pay_invoice result: %w", err)
	}

	// Return the full response data
	response := map[string]interface{}{
		"preimage":  payResult.Preimage,
		"fees_paid": payResult.FeesPaid,
		"invoice":   invoice,
		"wallet_id": walletID,
	}

	return response, nil
}

func (s *WalletService) PayInvoiceWithConnection(pubkey, secret, relay, invoice string) error {
	// Create temporary wallet connection
	wallet := &WalletConnection{
		NostrPubkey: pubkey,
		NostrSecret: secret,
		NostrRelay:  relay,
	}

	params := map[string]interface{}{
		"invoice": invoice,
	}

	ctx := context.Background()
	_, err := sendNWCRequest(ctx, wallet, "pay_invoice", params, 30*time.Second)
	return err
}

func (s *WalletService) MakeInvoice(walletID uuid.UUID, amountMsat int64, description string, expiry int64) (string, error) {
	wallet, err := s.Get(walletID)
	if err != nil {
		return "", err
	}

	params := map[string]interface{}{
		"amount":      amountMsat,
		"description": description,
		"expiry":      expiry,
	}

	ctx := context.Background()
	result, err := sendNWCRequest(ctx, wallet, "make_invoice", params, 30*time.Second)
	if err != nil {
		return "", err
	}

	// Parse the result
	var invoiceResult struct {
		Invoice string `json:"invoice"`
	}

	if err := json.Unmarshal(result, &invoiceResult); err != nil {
		return "", fmt.Errorf("failed to parse make_invoice result: %w", err)
	}

	return invoiceResult.Invoice, nil
}

func (s *WalletService) MakeChainAddress(walletID uuid.UUID) (string, error) {
	wallet, err := s.Get(walletID)
	if err != nil {
		return "", err
	}

	ctx := context.Background()
	result, err := sendNWCRequest(ctx, wallet, "make_chain_address", nil, 30*time.Second)
	if err != nil {
		return "", err
	}

	// Parse the result
	var addressResult struct {
		Address string `json:"address"`
	}

	if err := json.Unmarshal(result, &addressResult); err != nil {
		return "", fmt.Errorf("failed to parse make_chain_address result: %w", err)
	}

	return addressResult.Address, nil
}

func (s *WalletService) ListTransactions(walletID uuid.UUID, from, until int64, limit, offset int, unpaid bool, txType string) ([]byte, error) {
	wallet, err := s.Get(walletID)
	if err != nil {
		return nil, err
	}

	params := map[string]interface{}{}

	if from > 0 {
		params["from"] = from
	}
	if until > 0 {
		params["until"] = until
	}
	if limit > 0 {
		params["limit"] = limit
	}
	if offset > 0 {
		params["offset"] = offset
	}
	if unpaid {
		params["unpaid"] = unpaid
	}
	if txType != "" {
		params["type"] = txType
	}

	ctx := context.Background()
	result, err := sendNWCRequest(ctx, wallet, "list_transactions", params, 30*time.Second)
	if err != nil {
		return nil, err
	}

	// Create a full NWC response structure for compatibility
	fullResponse := NWCResponse{
		ResultType: "list_transactions",
		Result:     result,
	}

	return json.Marshal(fullResponse)
}

func (s *WalletService) GetBalance(walletID uuid.UUID) (int64, error) {
	wallet, err := s.Get(walletID)
	if err != nil {
		return 0, err
	}

	ctx := context.Background()
	result, err := sendNWCRequest(ctx, wallet, "get_balance", nil, 30*time.Second)
	if err != nil {
		return 0, err
	}

	// Parse the result
	var balanceResult struct {
		Balance int64 `json:"balance"`
	}

	if err := json.Unmarshal(result, &balanceResult); err != nil {
		return 0, fmt.Errorf("failed to parse get_balance result: %w", err)
	}

	return balanceResult.Balance, nil
}

func (s *WalletService) GetInfo(nostrPubkey, secret, relay string) ([]byte, error) {
	// Create temporary wallet connection
	wallet := &WalletConnection{
		NostrPubkey: nostrPubkey,
		NostrSecret: secret,
		NostrRelay:  relay,
	}

	ctx := context.Background()
	result, err := sendNWCRequest(ctx, wallet, "get_info", nil, 30*time.Second)
	if err != nil {
		return nil, err
	}

	// Create a full NWC response structure for compatibility
	fullResponse := NWCResponse{
		ResultType: "get_info",
		Result:     result,
	}

	return json.Marshal(fullResponse)
}

func (s *WalletService) ParseWalletConnectString(walletConnect string) (*WalletConnection, error) {
	return parseWalletConnectString(walletConnect)
}

type LnurlAddrResponse struct {
	Status         string `json:"status"`
	Tag            string `json:"tag"`
	CommentAllowed int    `json:"commentAllowed"`
	Callback       string `json:"callback"`
	Metadata       string `json:"metadata"`
	MinSendable    int    `json:"minSendable"`
	MaxSendable    int    `json:"maxSendable"`
	PayerData      struct {
		Name struct {
			Mandatory bool `json:"mandatory"`
		} `json:"name"`
		Email struct {
			Mandatory bool `json:"mandatory"`
		} `json:"email"`
		Pubkey struct {
			Mandatory bool `json:"mandatory"`
		} `json:"pubkey"`
	} `json:"payerData"`
	NostrPubkey string `json:"nostrPubkey"`
	AllowsNostr bool   `json:"allowsNostr"`
}

type LnurlCallbackResponse struct {
	Status        string `json:"status"`
	SuccessAction struct {
		Tag     string `json:"tag"`
		Message string `json:"message"`
	} `json:"successAction"`
	Verify string        `json:"verify"`
	Routes []interface{} `json:"routes"`
	PR     string        `json:"pr"`
}

// Helper functions for lightning address processing
func isValidEmail(email string) bool {
	parts := strings.Split(email, "@")
	return len(parts) == 2 && len(parts[0]) > 0 && len(parts[1]) > 0 && strings.Contains(parts[1], ".")
}

func splitEmail(email string) (string, string) {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return "", ""
	}
	return parts[0], parts[1]
}

func (s *WalletService) GetLnAddrCallbackUrl(address string) (string, error) {
	if !isValidEmail(address) {
		return "", fmt.Errorf("invalid lightning address")
	}

	handle, domain := splitEmail(address)
	endpoint := fmt.Sprintf("https://%s/.well-known/lnurlp/%s", domain, handle)

	resp, err := http.Get(endpoint)
	if err != nil {
		return "", fmt.Errorf("failed to make API call: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("API call failed with status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read API response: %w", err)
	}

	var lnAddrResponse LnurlAddrResponse
	if err := json.Unmarshal(body, &lnAddrResponse); err != nil {
		return "", fmt.Errorf("failed to parse API response: %w", err)
	}

	return lnAddrResponse.Callback, nil
}

func (s *WalletService) GetPRFromLnurl(endpoint string, mSatsAmount int64) (string, error) {
	separator := "?"
	if strings.Contains(endpoint, "?") {
		separator = "&"
	}

	url := fmt.Sprintf("%s%samount=%d", endpoint, separator, mSatsAmount)

	resp, err := http.Get(url)
	if err != nil {
		return "", fmt.Errorf("failed to make API call: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("API call failed with status code: %d, body: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read API response: %w", err)
	}

	var callbackResponse LnurlCallbackResponse
	if err := json.Unmarshal(body, &callbackResponse); err != nil {
		return "", fmt.Errorf("failed to parse API response: %w", err)
	}

	return callbackResponse.PR, nil
}

func (s *WalletService) PayLightningAddress(walletID uuid.UUID, lightningAddress string, amountSats int64) (map[string]interface{}, error) {
	// Convert satoshis to millisatoshis
	amountMsats := amountSats * 1000

	// Step 1: Get the callback URL from the lightning address
	callbackUrl, err := s.GetLnAddrCallbackUrl(lightningAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to get callback URL for lightning address: %w", err)
	}

	// Step 2: Get the payment request (invoice) from the callback URL
	invoice, err := s.GetPRFromLnurl(callbackUrl, amountMsats)
	if err != nil {
		return nil, fmt.Errorf("failed to get invoice from LNURL callback: %w", err)
	}

	// Step 3: Pay the invoice using existing wallet functionality
	response, err := s.PayInvoiceWithResponse(walletID, invoice)
	if err != nil {
		return nil, fmt.Errorf("failed to pay lightning address invoice: %w", err)
	}

	// Add lightning address info to response
	response["lightning_address"] = lightningAddress
	response["original_amount_sats"] = amountSats

	return response, nil
}
