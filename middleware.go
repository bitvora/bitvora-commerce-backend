package main

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

type contextKey string

const (
	UserContextKey    contextKey = "user"
	AccountContextKey contextKey = "account"
	APIKeyContextKey  contextKey = "api_key"
)

// Rate limiting structures
type RateLimitEntry struct {
	Count     int       `json:"count"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

type RateLimiter struct {
	ipLimits   sync.Map // map[string]*RateLimitEntry for IP-based limits
	userLimits sync.Map // map[string]*RateLimitEntry for user-based limits
	mutex      sync.RWMutex
}

type RateLimitConfig struct {
	MaxRequests int           // Maximum number of requests
	Window      time.Duration // Time window for the limit
	ByUser      bool          // If true, limit by user ID; if false, limit by IP
	RouteKey    string        // Unique key for this route's limits
}

var globalRateLimiter = &RateLimiter{}

// Cleanup routine to remove expired entries
func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	go func() {
		for range ticker.C {
			now := time.Now()

			// Clean IP limits
			rl.ipLimits.Range(func(key, value interface{}) bool {
				entry := value.(*RateLimitEntry)
				if now.Sub(entry.LastSeen) > time.Hour {
					rl.ipLimits.Delete(key)
				}
				return true
			})

			// Clean user limits
			rl.userLimits.Range(func(key, value interface{}) bool {
				entry := value.(*RateLimitEntry)
				if now.Sub(entry.LastSeen) > time.Hour {
					rl.userLimits.Delete(key)
				}
				return true
			})
		}
	}()
}

func init() {
	globalRateLimiter.cleanup()
}

// Get client IP address
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header first (in case of proxy)
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		// X-Forwarded-For can contain multiple IPs, take the first one
		ips := strings.Split(forwarded, ",")
		return strings.TrimSpace(ips[0])
	}

	// Check X-Real-IP header
	realIP := r.Header.Get("X-Real-IP")
	if realIP != "" {
		return realIP
	}

	// Fall back to RemoteAddr
	ip := r.RemoteAddr
	if colon := strings.LastIndex(ip, ":"); colon != -1 {
		ip = ip[:colon]
	}
	return ip
}

// Check if request is within rate limit
func (rl *RateLimiter) IsAllowed(identifier string, config RateLimitConfig) bool {
	now := time.Now()

	var limits *sync.Map
	if config.ByUser {
		limits = &rl.userLimits
	} else {
		limits = &rl.ipLimits
	}

	// Create a unique key combining route and identifier
	key := config.RouteKey + ":" + identifier

	entryInterface, exists := limits.Load(key)

	if !exists {
		// First request from this identifier for this route
		entry := &RateLimitEntry{
			Count:     1,
			FirstSeen: now,
			LastSeen:  now,
		}
		limits.Store(key, entry)
		return true
	}

	entry := entryInterface.(*RateLimitEntry)

	// Check if we're outside the time window
	if now.Sub(entry.FirstSeen) >= config.Window {
		// Reset the window
		entry.Count = 1
		entry.FirstSeen = now
		entry.LastSeen = now
		return true
	}

	// We're within the window, check if we've exceeded the limit
	if entry.Count >= config.MaxRequests {
		entry.LastSeen = now
		return false
	}

	// Increment the counter
	entry.Count++
	entry.LastSeen = now
	return true
}

// Rate limiting middleware factory
func RateLimitMiddleware(config RateLimitConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var identifier string

			if config.ByUser {
				// Try to get user from context for authenticated routes
				user, err := GetUserFromContext(r.Context())
				if err != nil {
					// If no user in context, fall back to IP-based limiting
					identifier = getClientIP(r)
				} else {
					identifier = user.ID.String()
				}
			} else {
				// IP-based limiting
				identifier = getClientIP(r)
			}

			if !globalRateLimiter.IsAllowed(identifier, config) {
				JsonResponse(w, http.StatusTooManyRequests, "Rate limit exceeded", map[string]interface{}{
					"limit":       config.MaxRequests,
					"window":      config.Window.String(),
					"retry_after": int(config.Window.Seconds()),
				})
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func CombinedAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		sessionIDStr := r.Header.Get("Session-ID")

		if sessionIDStr == "" && (authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ")) {
			JsonResponse(w, http.StatusUnauthorized, "Unauthorized", "No valid authentication provided")
			return
		}

		if sessionIDStr != "" {
			sessionID, err := uuid.Parse(sessionIDStr)
			if err != nil {
				JsonResponse(w, http.StatusUnauthorized, "Unauthorized", "Invalid session token format")
				return
			}

			session, ok := sessionCache.cache.Load(sessionID)
			if !ok || session == nil {
				session, err = sessionRepository.Get(sessionID)
				if err != nil || session == nil {
					JsonResponse(w, http.StatusUnauthorized, "Unauthorized", "Invalid session")
					return
				}
			}

			if session.Status != "active" {
				JsonResponse(w, http.StatusUnauthorized, "Unauthorized", "Session is not active")
				return
			}

			user, err := userService.Get(session.UserID)
			if err != nil {
				JsonResponse(w, http.StatusUnauthorized, "Unauthorized", "User not found")
				return
			}

			// Check if email is confirmed
			if user.EmailConfirmedAt == nil {
				JsonResponse(w, http.StatusPreconditionFailed, "Email not confirmed", "Please check your email and click the confirmation link to access your account.")
				return
			}

			ctx := context.WithValue(r.Context(), UserContextKey, user)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		if strings.HasPrefix(authHeader, "Bearer ") {
			token := strings.TrimPrefix(authHeader, "Bearer ")
			apiKey, err := AuthenticateAPIKey(token)
			if err != nil {
				JsonResponse(w, http.StatusUnauthorized, "Unauthorized", "Invalid API key")
				return
			}

			user, err := userService.Get(apiKey.UserID)
			if err != nil {
				JsonResponse(w, http.StatusUnauthorized, "Unauthorized", "User not found")
				return
			}

			// Check if email is confirmed
			if user.EmailConfirmedAt == nil {
				JsonResponse(w, http.StatusPreconditionFailed, "Email not confirmed", "Please check your email and click the confirmation link to access your account.")
				return
			}

			account, err := accountService.Get(apiKey.AccountID)
			if err != nil {
				JsonResponse(w, http.StatusUnauthorized, "Unauthorized", "Account not found")
				return
			}

			ctx := r.Context()
			ctx = context.WithValue(ctx, UserContextKey, user)
			ctx = context.WithValue(ctx, AccountContextKey, account)
			ctx = context.WithValue(ctx, APIKeyContextKey, apiKey)

			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}
	})
}

func GetUserFromContext(ctx context.Context) (*User, error) {
	user, ok := ctx.Value(UserContextKey).(*User)
	if !ok || user == nil {
		return nil, errors.New("no user found in context")
	}
	return user, nil
}

func GetAccountFromContext(ctx context.Context) (*Account, error) {
	account, ok := ctx.Value(AccountContextKey).(*Account)
	if !ok || account == nil {
		return nil, errors.New("no account found in context")
	}
	return account, nil
}

func GetAPIKeyFromContext(ctx context.Context) (*APIKey, error) {
	apiKey, ok := ctx.Value(APIKeyContextKey).(*APIKey)
	if !ok || apiKey == nil {
		return nil, errors.New("no API key found in context")
	}
	return apiKey, nil
}

func CheckAPIPermission(ctx context.Context, resource string, action string) bool {
	apiKey, err := GetAPIKeyFromContext(ctx)
	if err != nil {
		return false
	}

	var permission ResourcePermission

	switch resource {
	case "customers":
		permission = apiKey.Permissions.Customers
	case "products":
		permission = apiKey.Permissions.Products
	case "subscriptions":
		permission = apiKey.Permissions.Subscriptions
	case "payment_links":
		permission = apiKey.Permissions.PaymentLinks
	case "checkouts":
		permission = apiKey.Permissions.Checkouts
	case "wallets":
		permission = apiKey.Permissions.Wallets
	case "invoices":
		permission = apiKey.Permissions.Invoices
	case "webhooks":
		permission = apiKey.Permissions.Webhooks
	default:
		return false
	}

	switch action {
	case "read":
		return permission.Read
	case "create":
		return permission.Create
	case "update":
		return permission.Update
	case "delete":
		return permission.Delete
	default:
		return false
	}
}
