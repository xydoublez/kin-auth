package csrf

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/jban332/kin-openapi/openapi3"
	"github.com/jban332/kincore/weberrors"
	"github.com/jban332/kinauth"
	"github.com/jban332/kinlog"
	"net/http"
)

const httpStatusForSecurityFailure = http.StatusUnauthorized

var defaultCSRFCookieConfig = &auth.CookieConfig{
	Name: "XSRF-TOKEN",
}

type Engine struct {
	CookieConfig   *auth.CookieConfig
	SecurityScheme *openapi3.SecurityScheme
}

func (engine *Engine) NewCookie(c context.Context, state auth.State) (*http.Cookie, error) {
	cookieConfig := engine.CookieConfig
	if cookieConfig == nil {
		cookieConfig = defaultCSRFCookieConfig
	}
	cookie, err := cookieConfig.NewNonSecureCookie(c, state)
	if err != nil {
		return nil, err
	}
	if cookie.Name == "" {
		cookie.Name = "XSRF-TOKEN"
	}
	data := make([]byte, 16)
	n, err := rand.Read(data)
	if n < len(data) || err != nil {
		panic(err)
	}
	cookie.Value = hex.EncodeToString(data)
	return cookie, nil
}

func (engine *Engine) Authenticate(c context.Context, state auth.State, scopes []string) error {
	securityScheme := engine.SecurityScheme

	// Validate security scheme type
	switch securityScheme.Type {
	case "apiKey":
	default:
		msg := fmt.Sprintf("Anti-XSS security engine can't be used with a security scheme of type '%s'",
			securityScheme.Type)
		return weberrors.New(httpStatusForSecurityFailure, msg)
	}
	name := securityScheme.Name
	in := securityScheme.In

	// Get value of the token
	var value string
	switch in {
	case openapi3.ParameterInQuery:
		value = state.QueryParams().Get(name)
		if len(value) == 0 {
			msg := fmt.Sprintf("Query parameter '%s' is missing", name)
			return weberrors.New(httpStatusForSecurityFailure, msg)
		}
	case openapi3.ParameterInHeader:
		values := state.Request().Header[http.CanonicalHeaderKey(name)]
		if len(values) == 0 {
			msg := fmt.Sprintf("HTTP header '%s' is missing", name)
			return weberrors.New(httpStatusForSecurityFailure, msg)
		}
		value = values[0]
	default:
		return fmt.Errorf("Invalid security scheme 'in' value '%s'", in)
	}

	// Get cookie name
	cookieConfig := engine.CookieConfig
	if cookieConfig == nil {
		cookieConfig = defaultCSRFCookieConfig
	}
	cookieName := cookieConfig.Name
	if cookieName == "" {
		return weberrors.New(httpStatusForSecurityFailure,
			"Anti-XSS security engine configuration is missing cookie name")
	}

	// Get cookie value
	cookie, _ := state.Request().Cookie(cookieName)
	if cookie == nil {
		msg := fmt.Sprintf("Anti-XSS cookie '%s' is missing from the request", cookieName)
		return weberrors.New(httpStatusForSecurityFailure, msg)
	}
	cookieValue := cookie.Value
	if cookieValue == "" {
		msg := fmt.Sprintf("Anti-XSS cookie '%s' has empty value in the request", cookieName)
		return weberrors.New(httpStatusForSecurityFailure, msg)
	}

	// Ensure that the two values are equal
	if value == cookieValue {
		return nil
	}

	// Return error
	var where string
	switch securityScheme.In {
	case "header":
		where = "Anti-XSS HTTP header"
	case "query":
		where = "Anti-XSS query parameter"
	}
	auth.Logger.InfoC(c, "XSRF token is wrong",
		log.String("in", securityScheme.In))
	msg := fmt.Sprintf("%s '%s' ('%s') does not match value of the cookie '%s' ('%s')",
		where, securityScheme.Name, value, cookieName, cookieValue)
	return weberrors.New(httpStatusForSecurityFailure, msg)
}
