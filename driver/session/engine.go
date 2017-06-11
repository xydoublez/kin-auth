package session

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/jban332/kin-openapi/jsoninfo"
	"github.com/jban332/kin-openapi/openapi3"
	"github.com/jban332/kincore/jwt"
	"github.com/jban332/kinauth"
	"github.com/jban332/kinauth/openapi3auth"
	"net/http"
	"time"
)

func init() {
	// IMPORTANT: This is serious abuse of OpenAPI3 specification!
	//
	// In practice this should be ok as long as developers know what they do.
	openapi3auth.RegisterFactory("session", func(c context.Context, securitySchema *openapi3.SecurityScheme) (auth.Driver, error) {
		return &Engine{}, nil
	})
}

var defaultSessionCookieConfig = &auth.CookieConfig{
	Name: "session",
}

var _ auth.Driver = &Engine{}

// Engine describes how issue and verify session cookies.
type Engine struct {
	// MANDATORY: Cookie name, etc.
	// Failure to set these will result in errors or panics
	Cookie *auth.CookieConfig `json:"cookie"`

	// MANDATORY: JWT secret, etc.
	// Failure to set these will result in errors or panics
	JWT *jwt.Config `json:"jwt"`

	// Optional schema of the session object
	Schema *openapi3.Schema `json:"schema,omitempty"`
}

func (value *Engine) MarshalJSON() ([]byte, error) {
	return jsoninfo.MarshalStructFields(value)
}

func (value *Engine) UnmarshalJSON(data []byte) error {
	return jsoninfo.UnmarshalStructFields(data, value)
}

func (engine *Engine) GetCookieConfig() *auth.CookieConfig {
	cookieConfig := engine.Cookie
	if cookieConfig == nil {
		cookieConfig = defaultSessionCookieConfig
	}
	return cookieConfig
}

func (engine *Engine) Authenticate(c context.Context, state auth.State, scopes []string) error {
	session, err := engine.ReadCookie(c, state.Request())
	if err != nil {
		return err
	}
	if session.HasScopes(scopes) == false {
		return auth.ErrAuthFailed
	}
	return nil
}

func (engine *Engine) ReadCookie(c context.Context, req *http.Request) (*Session, error) {
	// Find cookie
	cookieConfig := engine.GetCookieConfig()
	cookie, err := req.Cookie(cookieConfig.Name)
	if err != nil {
		if err == http.ErrNoCookie {
			return nil, fmt.Errorf("Session cookie '%s' is missing from the received request", engine.Cookie.Name)
		}
		return nil, fmt.Errorf("Error in the received session cookie: %v", err)
	}

	// Decode JWT token
	//
	// DecodeString also does:
	//   * JWT expiration validation
	//   * JWT signature validation
	//   * JWT revocation check, if configured
	jwt := engine.JWT
	if jwt == nil {
		auth.Logger.Critical("Session driver doesn't have JWT configuration. Can't read session cookie.")
	}
	payloadBytes, err := jwt.DecodeString(c, cookie.Value)
	if err != nil {
		return nil, fmt.Errorf("Can't create session cookie because of a JWT problem: %v", err)
	}

	// Deserialize a session
	session := &Session{}
	err = json.Unmarshal(payloadBytes, session)
	if err != nil {
		return nil, fmt.Errorf("Serializing session failed: %v", err)
	}

	// Return session
	return session, nil
}

func (engine *Engine) NewCookie(c context.Context, state auth.State, session *Session) (*http.Cookie, error) {
	// Create new cookie
	cookieConfig := engine.GetCookieConfig()
	cookie, err := cookieConfig.NewSecureCookie(c, state)
	if err != nil {
		return nil, err
	}
	if session == nil {
		// Request client to destroy the cookie
		cookie.MaxAge = -1
	} else {
		// Serialize session
		data, err := json.Marshal(session)
		if err != nil {
			return nil, fmt.Errorf("Can't create session cookie because of session marshlling proble: %v", err)
		}

		// Encode JWT token
		token := engine.JWT.EncodeToString(c, data)
		if err != nil {
			return nil, fmt.Errorf("Can't create session cookie because of a JWT problem: %v", err)
		}

		// Set cookie value
		cookie.Value = token
	}

	// Calculate 'expires' for browser that don't support 'maxAge'
	if cookie.MaxAge >= 0 {
		maxAgeDuration := time.Duration(cookie.MaxAge) * time.Second
		cookie.Expires = time.Now().Add(maxAgeDuration)
	} else {
		cookie.Expires = time.Unix(0, 0)
	}

	// Done!
	return cookie, nil
}
