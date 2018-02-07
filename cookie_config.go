package auth

import (
	"context"
	"errors"
	"net/http"
	"time"
)

var ErrCookieRequiresTLS = errors.New("Can't create a secure cookie when request URL scheme is not HTTPS")

// CookieConfig is a helper type for security engines that use cookies
type CookieConfig struct {
	Name                 string `json:"name,omitempty"`
	Domain               string `json:"domain,omitempty"`
	Path                 string `json:"path,omitempty"`
	MaxAge               int    `json:"maxAge,omitempty"`
	ReadableByJavascript bool   `json:"readableByJavascript,omitempty"`
}

func (cookieConfig *CookieConfig) Validate(c context.Context) error {
	if cookieConfig.Name == "" {
		return errors.New("Cookie name can't be blank")
	}
	return nil
}

// NewSecureCookie returns a secure cookie that must not leak outside
// TLS-protected connection.
//
// If the HTTP request is not TLS-protected, returns an error.
func (cookieConfig CookieConfig) NewSecureCookie(c context.Context, state State) (*http.Cookie, error) {
	return cookieConfig.newCookie(c, state, true)
}

// NewNonSecureCookie returns a cookie that is allowed to leak to anyone
// who is listening to network traffic.
func (cookieConfig CookieConfig) NewNonSecureCookie(c context.Context, state State) (*http.Cookie, error) {
	return cookieConfig.newCookie(c, state, false)
}

func (cookieConfig CookieConfig) newCookie(c context.Context, state State, secure bool) (*http.Cookie, error) {
	req := state.Request()
	name := cookieConfig.Name
	if name == "" {
		return nil, errors.New("Cookie is missing name")
	}
	domain := cookieConfig.Domain
	if domain == "" {
		domain = req.Host
	}
	path := cookieConfig.Path
	if path == "" {
		path = "/"
	}
	maxAge := cookieConfig.MaxAge

	// Must use URL scheme to determine TLS because:
	// client<-->proxy connection may be non-TLS even when
	// proxy<-->server connection is TLS.
	if secure && req.URL.Scheme != "https" {
		return nil, ErrCookieRequiresTLS
	}

	// By default, cookies are NOT readable by Javascript.
	httpOnly := true
	if cookieConfig.ReadableByJavascript {
		httpOnly = false
	}

	// Default maxAge is 30 minutes
	if maxAge == 0 {
		maxAge = 1800
	}

	// Calculate "expires"
	expires := time.Now().Add(time.Duration(maxAge) * time.Second)

	return &http.Cookie{
		Name:     name,
		Domain:   domain,
		Path:     path,
		MaxAge:   maxAge,
		Expires:  expires,
		Secure:   secure,
		HttpOnly: httpOnly,
	}, nil
}
