package main

import (
	"context"
	"errors"
	"net/http"

	"github.com/google/uuid"
)

type contextKey string

const (
	UserContextKey contextKey = "user"
)

func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		sessionIDStr := r.Header.Get("Session-ID")
		if sessionIDStr == "" {
			JsonResponse(w, http.StatusUnauthorized, "Unauthorized", "No session token provided")
			return
		}

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
	})
}

func GetUserFromContext(ctx context.Context) (*User, error) {
	user, ok := ctx.Value(UserContextKey).(*User)
	if !ok || user == nil {
		return nil, errors.New("no user found in context")
	}
	return user, nil
}
