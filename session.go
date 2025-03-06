package main

import (
	"time"

	"github.com/google/uuid"
	"github.com/puzpuzpuz/xsync/v3"
)

type Session struct {
	ID           uuid.UUID  `db:"id" json:"id"`
	UserID       uuid.UUID  `db:"user_id" json:"user_id"`
	SessionToken string     `db:"session_token" json:"session_token"`
	LoggedInAt   time.Time  `db:"logged_in_at" json:"logged_in_at"`
	LoggedOutAt  *time.Time `db:"logged_out_at" json:"logged_out_at,omitempty"`
	Status       string     `db:"status" json:"status"`
}

type SessionRepository struct{}

var sessionRepository = &SessionRepository{}

type SessionCache struct {
	cache *xsync.MapOf[uuid.UUID, *Session]
}

var sessionCache = &SessionCache{
	cache: xsync.NewMapOf[uuid.UUID, *Session](),
}

func (r *SessionRepository) Create(session *Session) (*Session, error) {
	err := db.Get(session, "INSERT INTO sessions (id, user_id, session_token, logged_in_at, logged_out_at, status) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *", session.ID, session.UserID, session.SessionToken, session.LoggedInAt, session.LoggedOutAt, session.Status)
	if err == nil {
		sessionCache.cache.Store(session.ID, session)
	}
	return session, err
}

func (r *SessionRepository) Update(session *Session) error {
	_, err := db.Exec("UPDATE sessions SET user_id=$1, session_token=$2, logged_in_at=$3, logged_out_at=$4, status=$5 WHERE id=$6", session.UserID, session.SessionToken, session.LoggedInAt, session.LoggedOutAt, session.Status, session.ID)
	if err == nil {
		sessionCache.cache.Store(session.ID, session)
	}
	return err
}

func (r *SessionRepository) Get(id uuid.UUID) (*Session, error) {
	if session, ok := sessionCache.cache.Load(id); ok {
		return session, nil
	}
	session := &Session{}
	err := db.Get(session, "SELECT * FROM sessions WHERE id=$1", id)
	if err == nil {
		sessionCache.cache.Store(id, session)
	}
	return session, err
}

func (r *SessionRepository) Delete(id uuid.UUID) error {
	_, err := db.Exec("DELETE FROM sessions WHERE id=$1", id)
	if err == nil {
		sessionCache.cache.Delete(id)
	}
	return err
}

func (c *SessionCache) Invalidate(id uuid.UUID) {
	c.cache.Delete(id)
}
