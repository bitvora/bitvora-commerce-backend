package main

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/google/uuid"
)

type contextKey string

const (
	UserContextKey    contextKey = "user"
	AccountContextKey contextKey = "account"
	APIKeyContextKey  contextKey = "api_key"
)

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
