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
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip04"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/exp/slog"
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
var walletListener = NewWalletListener()

type ResponsePromise struct {
	Response chan []byte
	Timeout  *time.Timer
	UserData interface{}
}

type WalletListener struct {
	pool              *nostr.SimplePool
	ctx               context.Context
	cancelFunc        context.CancelFunc
	connections       sync.Map
	walletCache       *WalletCache
	walletPubkeyCache sync.Map
	pendingRequests   sync.Map
}

func NewWalletListener() *WalletListener {
	ctx, cancel := context.WithCancel(context.Background())
	return &WalletListener{
		pool:              nostr.NewSimplePool(ctx),
		ctx:               ctx,
		cancelFunc:        cancel,
		connections:       sync.Map{},
		walletCache:       walletCache,
		walletPubkeyCache: sync.Map{},
		pendingRequests:   sync.Map{},
	}
}

func (l *WalletListener) WaitForResponse(eventID string, timeout time.Duration, userData interface{}) ([]byte, error) {
	responseChan := make(chan []byte, 1)
	timer := time.NewTimer(timeout)

	l.pendingRequests.Store(eventID, &ResponsePromise{
		Response: responseChan,
		Timeout:  timer,
		UserData: userData,
	})

	defer func() {
		timer.Stop()
		l.pendingRequests.Delete(eventID)
	}()

	select {
	case response := <-responseChan:
		return response, nil
	case <-timer.C:
		return nil, fmt.Errorf("request timed out after %v", timeout)
	}
}

func (l *WalletListener) handleEvent(event nostr.Event) {
	slog.Info("Received event", "event_id", event.ID, "pubkey", event.PubKey, "content", event.Content)

	var requestID string
	for _, tag := range event.Tags {
		if len(tag) >= 2 && tag[0] == "e" {
			requestID = tag[1]
			break
		}
	}
	if requestID == "" {
		slog.Warn("No request ID found in event", "event_id", event.ID)
		return
	}

	promiseInterface, exists := l.pendingRequests.Load(requestID)
	if !exists {
		slog.Warn("No pending request found for request ID", "request_id", requestID)
		return
	}

	promise, ok := promiseInterface.(*ResponsePromise)
	if !ok {
		slog.Error("Invalid promise type for request ID", "request_id", requestID)
		return
	}

	var targetPubkey string
	for _, ptag := range event.Tags {
		if len(ptag) >= 2 && ptag[0] == "p" {
			targetPubkey = ptag[1]
			break
		}
	}
	if targetPubkey == "" {
		slog.Warn("No target pubkey found in event", "event_id", event.ID)
		return
	}

	walletInterface, found := l.walletPubkeyCache.Load(targetPubkey)
	if !found {
		if requestPromise, hasPromise := promise.UserData.(map[string]interface{}); hasPromise {
			if walletSecret, ok := requestPromise["wallet_secret"].(string); ok {
				slog.Debug("Using temporary wallet data for get_info response", "target_pubkey", targetPubkey)

				sharedSecret, err := nip04.ComputeSharedSecret(event.PubKey, walletSecret)
				if err != nil {
					slog.Error("Failed to compute shared secret for temp wallet", "error", err)
					return
				}

				decrypted, err := nip04.Decrypt(event.Content, sharedSecret)
				if err != nil {
					slog.Error("Failed to decrypt event content for temp wallet", "error", err)
					return
				}

				promise.Response <- []byte(decrypted)
				return
			}
		}

		slog.Warn("Wallet not found in cache for target pubkey", "target_pubkey", targetPubkey)
		return
	}

	wallet, ok := walletInterface.(*WalletConnection)
	if !ok {
		slog.Error("Invalid wallet type for target pubkey", "target_pubkey", targetPubkey)
		return
	}

	decryptedContent, err := l.decryptEventContent(wallet, event)
	if err != nil {
		slog.Error("Failed to decrypt event content", "event_id", event.ID, "error", err)
		return
	}

	slog.Info("Decrypted event content", "event_id", event.ID, "decrypted_content", decryptedContent)
	var paymentResponse struct {
		Result struct {
			PaymentHash string `json:"payment_hash"`
			Amount      int64  `json:"amount_msat"`
			Preimage    string `json:"preimage"`
			Invoice     string `json:"invoice,omitempty"`
		} `json:"result"`
		Error *struct{} `json:"error,omitempty"`
	}

	if err := json.Unmarshal([]byte(decryptedContent), &paymentResponse); err != nil {
		slog.Error("Failed to parse JSON from decrypted content", "event_id", event.ID, "error", err)
		return
	}

	if paymentResponse.Error != nil {
		slog.Warn("Payment error received", "event_id", event.ID, "error", paymentResponse.Error)
		return
	}

	checkouts := []*Checkout{}
	err = db.Select(&checkouts, "SELECT * FROM checkouts WHERE lightning_invoice=$1 AND state=$2",
		paymentResponse.Result.Invoice, CheckoutStateOpen)

	if err == nil && len(checkouts) > 0 {
		for _, checkout := range checkouts {
			newState := CheckoutStatePaid
			receivedAmount := paymentResponse.Result.Amount

			if receivedAmount < checkout.Amount {
				newState = CheckoutStateUnderpaid
			} else if receivedAmount > checkout.Amount {
				newState = CheckoutStateOverpaid
			}

			checkoutService.UpdateState(checkout.ID, newState, receivedAmount)
			slog.Info("Updated checkout state", "checkout_id", checkout.ID, "new_state", newState, "received_amount", receivedAmount)
		}
	}

	promise.Response <- []byte(decryptedContent)
}

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

		walletListener.AddWallet(createdWallet)
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

	slog.Info("no active wallet found", "account_id", accountID)
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

func (l *WalletListener) Start() error {
	err := l.loadWalletConnectionsToMemory()
	if err != nil {
		return fmt.Errorf("failed to load wallet connections to memory: %w", err)
	}

	wallets, err := walletRepository.GetActiveWalletConnections()
	if err != nil {
		return fmt.Errorf("failed to load active wallet connections: %w", err)
	}

	relays := make([]string, 0)
	for _, wallet := range wallets {
		relays = append(relays, wallet.NostrRelay)
	}

	relayMap := make(map[string]struct{})
	uniqueRelays := make([]string, 0)
	for _, relay := range relays {
		if _, exists := relayMap[relay]; !exists {
			relayMap[relay] = struct{}{}
			uniqueRelays = append(uniqueRelays, relay)
		}
	}

	l.SubscribeToRelays(uniqueRelays)

	return nil
}

func (l *WalletListener) loadWalletConnectionsToMemory() error {
	l.walletPubkeyCache = sync.Map{}

	wallets, err := walletRepository.GetActiveWalletConnections()
	if err != nil {
		return err
	}

	for _, wallet := range wallets {
		decryptedSecret, err := decrypt(wallet.NostrSecret)
		if err != nil {
			continue
		}

		derivedPubkey, err := nostr.GetPublicKey(decryptedSecret)
		if err != nil {
			continue
		}

		wallet.SecretPubkey = derivedPubkey

		l.walletPubkeyCache.Store(wallet.NostrPubkey, wallet)
		l.walletPubkeyCache.Store(derivedPubkey, wallet)
	}

	return nil
}

func (l *WalletListener) Stop() {
	l.cancelFunc()
	l.connections.Range(func(key, value interface{}) bool {
		if cancel, ok := value.(context.CancelFunc); ok {
			cancel()
		}
		return true
	})
}

func (l *WalletListener) SubscribeToRelays(relayURLs []string) {
	for _, relay := range relayURLs {
		l.EnsureRelaySubscription(relay)
	}
}

func (l *WalletListener) EnsureRelaySubscription(relayURL string) {
	relayKey := fmt.Sprintf("relay:%s", relayURL)
	_, isSubscribed := l.connections.Load(relayKey)

	if !isSubscribed {
		slog.Info("Ensuring subscription to relay", "relay", relayURL)

		ctx, cancel := context.WithCancel(l.ctx)
		l.connections.Store(relayKey, cancel)

		walletKinds := []int{
			nostr.KindNWCWalletInfo,
			nostr.KindNWCWalletRequest,
			nostr.KindNWCWalletResponse,
		}

		since := nostr.Timestamp(time.Now().Unix())
		filters := nostr.Filter{
			Kinds: walletKinds,
			Since: &since,
		}

		go func() {
			sub := l.pool.SubscribeMany(ctx, []string{relayURL}, filters)
			slog.Debug("Started relay subscription", "relay", relayURL)

			for event := range sub {
				if event.Event == nil {
					continue
				}

				l.handleEvent(*event.Event)
			}

			slog.Info("Relay subscription ended", "relay", relayURL)
		}()

		// Give the subscription a moment to establish
		time.Sleep(100 * time.Millisecond)
	}
}

func (l *WalletListener) decryptEventContent(wallet *WalletConnection, event nostr.Event) (string, error) {
	slog.Debug("Attempting to decrypt event content",
		"event_id", event.ID,
		"wallet_id", wallet.ID,
		"wallet_pubkey", wallet.NostrPubkey,
		"secret_length", len(wallet.NostrSecret))

	var walletPrivateKey string

	if len(wallet.NostrSecret) == 64 || len(wallet.NostrSecret) == 32 {
		walletPrivateKey = wallet.NostrSecret
	} else {
		var err error
		walletPrivateKey, err = decrypt(wallet.NostrSecret)
		if err != nil {
			return "", fmt.Errorf("failed to decrypt wallet secret: %w", err)
		}
		slog.Debug("Successfully decrypted wallet secret", "event_id", event.ID)
	}

	sharedSecret, err := nip04.ComputeSharedSecret(event.PubKey, walletPrivateKey)
	if err != nil {
		return "", fmt.Errorf("failed to compute shared secret: %w", err)
	}

	decrypted, err := nip04.Decrypt(event.Content, sharedSecret)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt content: %w", err)
	}

	return decrypted, nil
}

func (l *WalletListener) encryptEventContent(wallet *WalletConnection, recipientPubkey, content string) (string, error) {
	var walletPrivateKey string

	if len(wallet.NostrSecret) == 64 || len(wallet.NostrSecret) == 32 {
		walletPrivateKey = wallet.NostrSecret
	} else {
		var err error
		walletPrivateKey, err = decrypt(wallet.NostrSecret)
		if err != nil {
			return "", fmt.Errorf("failed to decrypt wallet secret: %w", err)
		}
	}

	sharedSecret, err := nip04.ComputeSharedSecret(recipientPubkey, walletPrivateKey)
	if err != nil {
		return "", fmt.Errorf("failed to compute shared secret: %w", err)
	}

	encrypted, err := nip04.Encrypt(content, sharedSecret)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt content: %w", err)
	}

	return encrypted, nil
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

	request := struct {
		Method string `json:"method"`
		Params struct {
			Invoice string `json:"invoice"`
		} `json:"params"`
	}{
		Method: "pay_invoice",
		Params: struct {
			Invoice string `json:"invoice"`
		}{
			Invoice: invoice,
		},
	}

	requestJSON, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	sharedSecret, err := nip04.ComputeSharedSecret(wallet.NostrPubkey, wallet.NostrSecret)
	if err != nil {
		return fmt.Errorf("failed to compute shared secret: %w", err)
	}

	encryptedContent, err := nip04.Encrypt(string(requestJSON), sharedSecret)
	if err != nil {
		return fmt.Errorf("failed to encrypt content: %w", err)
	}

	event := nostr.Event{
		Kind:      nostr.KindNWCWalletRequest,
		PubKey:    wallet.NostrPubkey,
		CreatedAt: nostr.Now(),
		Content:   encryptedContent,
		Tags:      nostr.Tags{nostr.Tag{"p", wallet.NostrPubkey}},
	}

	event.Sign(wallet.NostrSecret)

	if walletListener != nil {
		walletListener.pool.PublishMany(walletListener.ctx, []string{wallet.NostrRelay}, event)

		responseData, err := walletListener.WaitForResponse(event.ID, 30*time.Second, nil)
		if err != nil {
			return fmt.Errorf("error waiting for payment: %w", err)
		}

		var response struct {
			Result struct {
				Preimage string `json:"preimage"`
				FeesPaid int64  `json:"fees_paid"`
			} `json:"result"`
			Error *struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error,omitempty"`
		}

		if err := json.Unmarshal(responseData, &response); err != nil {
			return fmt.Errorf("failed to parse payment response: %w", err)
		}

		if response.Error != nil {
			return fmt.Errorf("wallet error: %s - %s", response.Error.Code, response.Error.Message)
		}

		return nil
	} else {
		ctx := context.Background()
		pool := nostr.NewSimplePool(ctx)
		pool.PublishMany(ctx, []string{wallet.NostrRelay}, event)
		return fmt.Errorf("wallet listener not initialized, cannot wait for response")
	}
}

func (s *WalletService) MakeInvoice(walletID uuid.UUID, amountMsat int64, description string, expiry int64) (string, error) {
	wallet, err := s.Get(walletID)
	if err != nil {
		return "", err
	}

	request := struct {
		Method string `json:"method"`
		Params struct {
			Amount      int64  `json:"amount"`
			Description string `json:"description"`
			Expiry      int64  `json:"expiry"`
		} `json:"params"`
	}{
		Method: "make_invoice",
		Params: struct {
			Amount      int64  `json:"amount"`
			Description string `json:"description"`
			Expiry      int64  `json:"expiry"`
		}{
			Amount:      amountMsat,
			Description: description,
			Expiry:      expiry,
		},
	}

	requestJSON, err := json.Marshal(request)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	sharedSecret, err := nip04.ComputeSharedSecret(wallet.NostrPubkey, wallet.NostrSecret)
	if err != nil {
		return "", fmt.Errorf("failed to compute shared secret: %w", err)
	}

	encryptedContent, err := nip04.Encrypt(string(requestJSON), sharedSecret)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt content: %w", err)
	}

	event := nostr.Event{
		Kind:      nostr.KindNWCWalletRequest,
		PubKey:    wallet.NostrPubkey,
		CreatedAt: nostr.Now(),
		Content:   encryptedContent,
		Tags:      nostr.Tags{nostr.Tag{"p", wallet.NostrPubkey}},
	}

	event.Sign(wallet.NostrSecret)

	if walletListener != nil {
		walletListener.pool.PublishMany(walletListener.ctx, []string{wallet.NostrRelay}, event)

		responseData, err := walletListener.WaitForResponse(event.ID, 30*time.Second, nil)
		if err != nil {
			return "", fmt.Errorf("error waiting for invoice: %w", err)
		}

		var response struct {
			Result struct {
				Invoice string `json:"invoice"`
			} `json:"result"`
			Error *struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error,omitempty"`
		}

		if err := json.Unmarshal(responseData, &response); err != nil {
			return "", fmt.Errorf("failed to parse invoice response: %w", err)
		}

		if response.Error != nil {
			return "", fmt.Errorf("wallet error: %s - %s", response.Error.Code, response.Error.Message)
		}

		return response.Result.Invoice, nil
	} else {
		ctx := context.Background()
		pool := nostr.NewSimplePool(ctx)
		pool.PublishMany(ctx, []string{wallet.NostrRelay}, event)
		return "", fmt.Errorf("wallet listener not initialized, cannot wait for response")
	}
}

func (s *WalletService) MakeChainAddress(walletID uuid.UUID) (string, error) {
	wallet, err := s.Get(walletID)
	if err != nil {
		return "", err
	}

	request := struct {
		Method string `json:"method"`
		Params struct {
		} `json:"params"`
	}{
		Method: "make_chain_address",
		Params: struct{}{},
	}

	requestJSON, err := json.Marshal(request)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	sharedSecret, err := nip04.ComputeSharedSecret(wallet.NostrPubkey, wallet.NostrSecret)
	if err != nil {
		return "", fmt.Errorf("failed to compute shared secret: %w", err)
	}

	encryptedContent, err := nip04.Encrypt(string(requestJSON), sharedSecret)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt content: %w", err)
	}

	event := nostr.Event{
		Kind:      nostr.KindNWCWalletRequest,
		PubKey:    wallet.NostrPubkey,
		CreatedAt: nostr.Now(),
		Content:   encryptedContent,
		Tags:      nostr.Tags{nostr.Tag{"p", wallet.NostrPubkey}},
	}

	event.Sign(wallet.NostrSecret)

	if walletListener != nil {
		walletListener.pool.PublishMany(walletListener.ctx, []string{wallet.NostrRelay}, event)
	}

	responseData, err := walletListener.WaitForResponse(event.ID, 30*time.Second, nil)
	if err != nil {
		return "", fmt.Errorf("error waiting for chain address: %w", err)
	}

	var response struct {
		Result struct {
			Address string `json:"address"`
		} `json:"result"`
		Error *struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error,omitempty"`
	}

	if err := json.Unmarshal(responseData, &response); err != nil {
		return "", fmt.Errorf("failed to parse chain address response: %w", err)
	}

	if response.Error != nil {
		return "", fmt.Errorf("wallet error: %s - %s", response.Error.Code, response.Error.Message)
	}

	return response.Result.Address, nil
}

func (s *WalletService) UpdateWalletConnectionsCache() error {
	if walletListener != nil {
		return walletListener.loadWalletConnectionsToMemory()
	}
	return nil
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

	request := struct {
		Method string                 `json:"method"`
		Params map[string]interface{} `json:"params"`
	}{
		Method: "list_transactions",
		Params: params,
	}

	requestJSON, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	sharedSecret, err := nip04.ComputeSharedSecret(wallet.NostrPubkey, wallet.NostrSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to compute shared secret: %w", err)
	}

	encryptedContent, err := nip04.Encrypt(string(requestJSON), sharedSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt content: %w", err)
	}

	event := nostr.Event{
		Kind:      nostr.KindNWCWalletRequest,
		PubKey:    wallet.NostrPubkey,
		CreatedAt: nostr.Now(),
		Content:   encryptedContent,
		Tags:      nostr.Tags{nostr.Tag{"p", wallet.NostrPubkey}},
	}

	event.Sign(wallet.NostrSecret)

	if walletListener != nil {
		walletListener.pool.PublishMany(walletListener.ctx, []string{wallet.NostrRelay}, event)

		responseData, err := walletListener.WaitForResponse(event.ID, 30*time.Second, nil)
		if err != nil {
			return nil, fmt.Errorf("error waiting for transactions: %w", err)
		}

		var response struct {
			Result json.RawMessage `json:"result"`
			Error  *struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error,omitempty"`
		}

		if err := json.Unmarshal(responseData, &response); err != nil {
			return nil, fmt.Errorf("failed to parse transaction list response: %w", err)
		}

		if response.Error != nil {
			return nil, fmt.Errorf("wallet error: %s - %s", response.Error.Code, response.Error.Message)
		}

		return responseData, nil
	}

	return nil, fmt.Errorf("wallet listener not initialized, cannot wait for response")
}

func (s *WalletService) GetInfo(nostrPubkey, secret, relay string) ([]byte, error) {
	if walletListener != nil {
		walletListener.EnsureRelaySubscription(relay)
	}

	wallet := &WalletConnection{
		NostrPubkey: nostrPubkey,
		NostrSecret: secret,
		NostrRelay:  relay,
	}

	request := struct {
		Method string   `json:"method"`
		Params struct{} `json:"params"`
	}{
		Method: "get_info",
		Params: struct{}{},
	}

	requestJSON, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	sharedSecret, err := nip04.ComputeSharedSecret(wallet.NostrPubkey, wallet.NostrSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to compute shared secret: %w", err)
	}

	encryptedContent, err := nip04.Encrypt(string(requestJSON), sharedSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt content: %w", err)
	}

	event := nostr.Event{
		Kind:      nostr.KindNWCWalletRequest,
		PubKey:    wallet.NostrPubkey,
		CreatedAt: nostr.Now(),
		Content:   encryptedContent,
		Tags:      nostr.Tags{nostr.Tag{"p", wallet.NostrPubkey}},
	}

	event.Sign(wallet.NostrSecret)

	walletListener.pool.PublishMany(walletListener.ctx, []string{wallet.NostrRelay}, event)

	tempData := map[string]interface{}{
		"wallet_secret": wallet.NostrSecret,
	}
	responseData, err := walletListener.WaitForResponse(event.ID, 30*time.Second, tempData)
	if err != nil {
		return nil, fmt.Errorf("error waiting for info: %w", err)
	}

	var response struct {
		ResultType string `json:"result_type"`
		Result     struct {
			Alias         string   `json:"alias"`
			Color         string   `json:"color"`
			Pubkey        string   `json:"pubkey"`
			Network       string   `json:"network"`
			BlockHeight   int      `json:"block_height"`
			BlockHash     string   `json:"block_hash"`
			Methods       []string `json:"methods"`
			Notifications []string `json:"notifications"`
		} `json:"result"`
		Error *struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error,omitempty"`
	}

	if err := json.Unmarshal(responseData, &response); err != nil {
		return nil, fmt.Errorf("failed to parse info response: %w", err)
	}

	if response.Error != nil {
		return nil, fmt.Errorf("wallet error: %s - %s", response.Error.Code, response.Error.Message)
	}

	return responseData, nil
}

func (l *WalletListener) AddWallet(wallet *WalletConnection) {
	slog.Info("Adding wallet to listener cache",
		"wallet_id", wallet.ID,
		"pubkey", wallet.NostrPubkey,
		"relay", wallet.NostrRelay)

	l.walletPubkeyCache.Store(wallet.NostrPubkey, wallet)
	l.walletPubkeyCache.Store(wallet.SecretPubkey, wallet)

	l.EnsureRelaySubscription(wallet.NostrRelay)
}
