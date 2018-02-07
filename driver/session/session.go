package session

import (
	"sort"
	"time"
)

type SessionRequirements [][]string

// Session contain information about the current session
type Session struct {
	// Optional expiration.
	ExpiresAt time.Time `json:"exp,omitempty"` // "exp" recommended by JWT spec

	// Optional user identifier
	UserID string `json:"sub,omitempty"` // "sub" recommended by JWT spec

	// Optional session identifier
	SessionID string `json:"sid,omitempty"`

	// Optional scopes.
	Scopes []string `json:"sco,omitempty"`
}

func NewSessionFrom(old *Session) *Session {
	// Clone session
	clone := &Session{}
	*clone = *old

	// Clone scopes
	scopesClone := make([]string, len(old.Scopes))
	copy(scopesClone, old.Scopes)
	clone.Scopes = scopesClone

	// OK
	return clone
}

// WithScopes adds scopes.
// Each scope is added only if the session doesn't already have the scope.
// In the end, sorts scopes.
func (session *Session) WithScopes(scopes ...string) *Session {
	for _, scope := range scopes {
		if session.HasScope(scope) == false {
			session.Scopes = append(session.Scopes, scope)
		}
	}
	sort.Strings(session.Scopes)
	return session
}

func (session *Session) HasScope(scope string) bool {
	for _, item := range session.Scopes {
		if item == scope {
			return true
		}
	}
	return false
}

func (session *Session) HasScopes(scopes []string) bool {
	for _, item := range scopes {
		if session.HasScope(item) == false {
			return false
		}
	}
	return true
}
