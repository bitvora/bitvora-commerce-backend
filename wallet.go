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
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip04"
	log "github.com/sirupsen/logrus"
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
	ID           uuid.UUID  `db:"id" json:"id"`
	UserID       uuid.UUID  `db:"user_id" json:"user_id"`
	AccountID    uuid.UUID  `db:"account_id" json:"account_id"`
	NostrPubkey  string     `db:"nostr_pubkey" json:"nostr_pubkey"`
	NostrSecret  string     `db:"nostr_secret" json:"nostr_secret"`
	NostrRelay   string     `db:"nostr_relay" json:"nostr_relay"`
	SecretPubkey string     `db:"-" json:"-"`
	Active       bool       `db:"active" json:"active"`
	CreatedAt    time.Time  `db:"created_at" json:"created_at"`
	UpdatedAt    time.Time  `db:"updated_at" json:"updated_at"`
	ExpiredAt    *time.Time `db:"expired_at" json:"expired_at,omitempty"`
	DeletedAt    *time.Time `db:"deleted_at" json:"deleted_at,omitempty"`
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

func (l *WalletListener) WaitForResponse(eventID string, timeout time.Duration) ([]byte, error) {
	responseChan := make(chan []byte, 1)
	timer := time.NewTimer(timeout)

	l.pendingRequests.Store(eventID, &ResponsePromise{
		Response: responseChan,
		Timeout:  timer,
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
	// Find request ID
	var requestID string
	for _, tag := range event.Tags {
		if len(tag) >= 2 && tag[0] == "e" {
			requestID = tag[1]
			break
		}
	}
	if requestID == "" {
		return // No request ID found
	}

	// Get the promise from pending requests
	promiseInterface, exists := l.pendingRequests.Load(requestID)
	if !exists {
		return // No pending request found
	}

	promise, ok := promiseInterface.(*ResponsePromise)
	if !ok {
		return // Invalid promise type
	}

	// Find target pubkey
	var targetPubkey string
	for _, ptag := range event.Tags {
		if len(ptag) >= 2 && ptag[0] == "p" {
			targetPubkey = ptag[1]
			break
		}
	}
	if targetPubkey == "" {
		return // No target pubkey found
	}

	// Get wallet from cache
	walletInterface, found := l.walletPubkeyCache.Load(targetPubkey)
	if !found {
		return // Wallet not found
	}

	wallet, ok := walletInterface.(*WalletConnection)
	if !ok {
		return // Invalid wallet type
	}

	// Decrypt event content
	decryptedContent, err := l.decryptEventContent(wallet, event)
	if err != nil {
		return // Failed to decrypt content
	}

	log.Info("handling event", decryptedContent)

	// Parse payment response
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
		return // Failed to parse JSON
	}

	if paymentResponse.Error != nil {
		return // Payment error
	}

	// Process checkouts
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
		}
	}

	// Send response back
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
			created_at, updated_at, expired_at, deleted_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11
		) RETURNING *`,
		wallet.ID, wallet.UserID, wallet.AccountID, wallet.NostrPubkey, wallet.NostrSecret, wallet.NostrRelay, wallet.Active,
		wallet.CreatedAt, wallet.UpdatedAt, wallet.ExpiredAt, wallet.DeletedAt)

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

	derivedPubkey, err := nostr.GetPublicKey(wallet.NostrSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to derive public key from secret: %w", err)
	}
	wallet.SecretPubkey = derivedPubkey

	err = walletRepository.DeactivateOtherWallets(wallet.UserID, wallet.AccountID)
	if err != nil {
		return nil, err
	}

	createdWallet, err := walletRepository.Create(wallet)
	if err == nil && createdWallet != nil {
		walletCache.Set(createdWallet)
		if walletListener != nil {
			walletListener.walletPubkeyCache.Store(createdWallet.NostrPubkey, createdWallet)
			walletListener.walletPubkeyCache.Store(createdWallet.SecretPubkey, createdWallet)
		}
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
	ctx, cancel := context.WithCancel(l.ctx)

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

	sub := l.pool.SubscribeMany(ctx, relayURLs, filters)

	l.connections.Store("all_relays", cancel)

	go func() {
		for event := range sub {
			if event.Event == nil {
				continue
			}

			l.handleEvent(*event.Event)
		}

		l.connections.Delete("all_relays")
	}()
}

func (l *WalletListener) decryptEventContent(wallet *WalletConnection, event nostr.Event) (string, error) {
	walletPrivateKey, err := decrypt(wallet.NostrSecret)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt wallet secret: %w", err)
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
	walletPrivateKey, err := decrypt(wallet.NostrSecret)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt wallet secret: %w", err)
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

		responseData, err := walletListener.WaitForResponse(event.ID, 30*time.Second)
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

		responseData, err := walletListener.WaitForResponse(event.ID, 30*time.Second)
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

	responseData, err := walletListener.WaitForResponse(event.ID, 30*time.Second)
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
