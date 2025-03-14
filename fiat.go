package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
)

// ExchangeRates contains the exchange rates for Bitcoin to various fiat currencies
type ExchangeRates struct {
	Rates     map[string]float64 `json:"rates"`
	UpdatedAt time.Time          `json:"updated_at"`
}

// FiatRateService handles fetching and caching of BTC/fiat exchange rates
type FiatRateService struct {
	rates      ExchangeRates
	mu         sync.RWMutex
	ctx        context.Context
	cancelFunc context.CancelFunc
}

// NewFiatRateService creates a new exchange rate service with background updates
func NewFiatRateService() *FiatRateService {
	ctx, cancel := context.WithCancel(context.Background())
	service := &FiatRateService{
		rates: ExchangeRates{
			Rates:     make(map[string]float64),
			UpdatedAt: time.Time{},
		},
		ctx:        ctx,
		cancelFunc: cancel,
	}

	// Initial fetch of rates
	if err := service.updateRates(); err != nil {
		logger.Error("Failed to perform initial exchange rate fetch", "error", err)
	}

	// Start background updater
	go service.startRateUpdater()

	return service
}

// startRateUpdater runs a ticker to update the exchange rates periodically
func (s *FiatRateService) startRateUpdater() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := s.updateRates(); err != nil {
				logger.Error("Failed to update exchange rates", "error", err)
			} else {
				logger.Debug("Exchange rates updated successfully")
			}
		case <-s.ctx.Done():
			logger.Info("Exchange rate updater shutting down")
			return
		}
	}
}

// updateRates fetches the latest exchange rates from the API
func (s *FiatRateService) updateRates() error {
	// List of currencies to fetch
	currencies := []string{
		"usd", "eur", "jpy", "gbp", "aud", "cad", "chf", "cny", "hkd", "nzd",
	}

	url := fmt.Sprintf("https://api.coingecko.com/api/v3/simple/price?ids=bitcoin&vs_currencies=%s",
		formatCurrencyParam(currencies))

	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("failed to fetch exchange rates: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("received non-OK response from API: %d", resp.StatusCode)
	}

	var result map[string]map[string]float64
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("failed to decode API response: %w", err)
	}

	btcRates, ok := result["bitcoin"]
	if !ok {
		return fmt.Errorf("bitcoin rates not found in API response")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.rates.Rates = btcRates
	s.rates.UpdatedAt = time.Now()

	// Log the updated rates
	logger.Info("Updated exchange rates", "rates", s.rates.Rates)

	return nil
}

// formatCurrencyParam joins currency codes into a comma-separated list
func formatCurrencyParam(currencies []string) string {
	result := ""
	for i, curr := range currencies {
		if i > 0 {
			result += ","
		}
		result += curr
	}
	return result
}

// GetRates returns the current exchange rates
func (s *FiatRateService) GetRates() ExchangeRates {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Make a copy to avoid data races
	ratesCopy := ExchangeRates{
		Rates:     make(map[string]float64, len(s.rates.Rates)),
		UpdatedAt: s.rates.UpdatedAt,
	}

	for k, v := range s.rates.Rates {
		ratesCopy.Rates[k] = v
	}

	return ratesCopy
}

// GetRate gets the exchange rate for a specific currency
func (s *FiatRateService) GetRate(currency string) (float64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rate, ok := s.rates.Rates[currency]
	if !ok {
		return 0, fmt.Errorf("exchange rate not available for currency: %s", currency)
	}

	return rate, nil
}

// SatoshisToFiat converts satoshis to a fiat amount
func (s *FiatRateService) SatoshisToFiat(satoshis int64, currency string) (float64, error) {
	rate, err := s.GetRate(currency)
	if err != nil {
		return 0, err
	}

	// Convert satoshis to BTC (1 BTC = 100,000,000 satoshis)
	btcAmount := float64(satoshis) / 100000000.0

	// Convert BTC to fiat
	fiatAmount := btcAmount * rate

	return fiatAmount, nil
}

// FiatToSatoshis converts a fiat amount to satoshis
func (s *FiatRateService) FiatToSatoshis(fiatAmount float64, currency string) (int64, error) {
	rate, err := s.GetRate(currency)
	if err != nil {
		return 0, err
	}

	// Don't divide by zero
	if rate == 0 {
		return 0, fmt.Errorf("exchange rate for %s is zero", currency)
	}

	// Convert fiat to BTC
	btcAmount := fiatAmount / rate

	// Convert BTC to satoshis (1 BTC = 100,000,000 satoshis)
	satoshis := int64(btcAmount * 100000000.0)

	return satoshis, nil
}

// Stop gracefully stops the background updater
func (s *FiatRateService) Stop() {
	s.cancelFunc()
}

// FiatHandler handles HTTP requests related to fiat conversions
type FiatHandler struct {
	Validator *validator.Validate
	Service   *FiatRateService
}

// GetRates returns all available exchange rates
func (h *FiatHandler) GetRates(w http.ResponseWriter, r *http.Request) {
	rates := h.Service.GetRates()
	JsonResponse(w, http.StatusOK, "Exchange rates retrieved successfully", rates)
}

// ConvertSatoshisToFiat converts the given satoshi amount to the specified fiat currency
func (h *FiatHandler) ConvertSatoshisToFiat(w http.ResponseWriter, r *http.Request) {
	currency := chi.URLParam(r, "currency")
	if currency == "" {
		JsonResponse(w, http.StatusBadRequest, "Currency is required", nil)
		return
	}

	satoshisStr := r.URL.Query().Get("satoshis")
	if satoshisStr == "" {
		JsonResponse(w, http.StatusBadRequest, "Satoshis parameter is required", nil)
		return
	}

	satoshis, err := strconv.ParseInt(satoshisStr, 10, 64)
	if err != nil {
		JsonResponse(w, http.StatusBadRequest, "Invalid satoshis value", err.Error())
		return
	}

	fiatAmount, err := h.Service.SatoshisToFiat(satoshis, currency)
	if err != nil {
		JsonResponse(w, http.StatusBadRequest, "Conversion failed", err.Error())
		return
	}

	result := map[string]interface{}{
		"sats":        satoshis,
		"currency":    currency,
		"fiat_amount": fiatAmount,
	}

	JsonResponse(w, http.StatusOK, "Conversion successful", result)
}

// ConvertFiatToSatoshis converts the given fiat amount to satoshis
func (h *FiatHandler) ConvertFiatToSatoshis(w http.ResponseWriter, r *http.Request) {
	currency := chi.URLParam(r, "currency")
	if currency == "" {
		JsonResponse(w, http.StatusBadRequest, "Currency is required", nil)
		return
	}

	fiatStr := r.URL.Query().Get("amount")
	if fiatStr == "" {
		JsonResponse(w, http.StatusBadRequest, "Amount parameter is required", nil)
		return
	}

	fiatAmount, err := strconv.ParseFloat(fiatStr, 64)
	if err != nil {
		JsonResponse(w, http.StatusBadRequest, "Invalid fiat amount", err.Error())
		return
	}

	satoshis, err := h.Service.FiatToSatoshis(fiatAmount, currency)
	if err != nil {
		JsonResponse(w, http.StatusBadRequest, "Conversion failed", err.Error())
		return
	}

	result := map[string]interface{}{
		"currency":    currency,
		"fiat_amount": fiatAmount,
		"sats":        satoshis,
	}

	JsonResponse(w, http.StatusOK, "Conversion successful", result)
}
