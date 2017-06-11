package apikey

import (
	"context"
	"encoding/base64"
	"fmt"
	"github.com/jban332/kin-openapi/openapi3"
	"github.com/jban332/kin/core/jwt"
	"github.com/jban332/kin/core/weberrors"
	"github.com/jban332/kin/service/auth"
	"net/http"
	"strings"
)

const httpStatusForSecurityFailure = http.StatusUnauthorized

var (
	ErrAPIKeyMissing    = weberrors.New(httpStatusForSecurityFailure, "API key is missing")
	ErrAPIKeyNotCorrect = weberrors.New(httpStatusForSecurityFailure, "API key is incorrect")

	ErrAuthorizationHeaderMissing          = weberrors.New(httpStatusForSecurityFailure, "HTTP header 'Authorization' is missing")
	ErrAuthorizationHeaderNotBasic         = weberrors.New(httpStatusForSecurityFailure, "HTTP header 'Authorization' should start with 'Basic '")
	ErrAuthorizationHeaderNotBearer        = weberrors.New(httpStatusForSecurityFailure, "HTTP header 'Authorization' should start with 'Bearer '")
	ErrAuthorizationHeaderNotValidBasic    = weberrors.New(httpStatusForSecurityFailure, "HTTP header 'Authorization' should be valid base64-encoded username:password")
	ErrAuthorizationHeaderNotCorrectBasic  = weberrors.New(httpStatusForSecurityFailure, "Incorrect user name or password")
	ErrAuthorizationHeaderNotCorrectBearer = weberrors.New(httpStatusForSecurityFailure, "Incorrect API key")
)

type ValidationInput struct {
	State  auth.State
	Scopes []string
	APIKey string
}

type Engine struct {
	SecurityScheme   *openapi3.SecurityScheme
	KeyValidatorFunc func(c context.Context, input *ValidationInput) error
	Realm            string
}

func (engine *Engine) Authenticate(c context.Context, state auth.State, scopes []string) error {
	f := engine.KeyValidatorFunc
	if f == nil {
		return weberrors.New(httpStatusForSecurityFailure, "API key security engine configuration is missing key validator function")
	}
	apiKey, err := getAPIKeyValue(state, engine.SecurityScheme)
	if err != nil {
		return err
	}
	return f(c, &ValidationInput{
		State:  state,
		Scopes: scopes,
		APIKey: apiKey,
	})
}

func (engine *Engine) WithJWT(jwtConfig *jwt.Config) *Engine {
	engine.KeyValidatorFunc = func(c context.Context, input *ValidationInput) error {
		data, err := jwtConfig.DecodeString(c, input.APIKey)
		if err != nil {
			return err
		}
		if err := jwt.CheckNotExpired(data); err != nil {
			return weberrors.NewFrom(httpStatusForSecurityFailure, err)
		}
		jwtConfig.CheckNotRevoked(c, data)
		return nil
	}
	return engine
}

func getAPIKeyValue(state auth.State, securityScheme *openapi3.SecurityScheme) (string, error) {
	switch securityScheme.Type {
	case "apiKey":
		name := securityScheme.Name
		in := securityScheme.In
		switch in {
		case openapi3.ParameterInQuery:
			value := state.QueryParams().Get(name)
			if len(value) == 0 {
				msg := fmt.Sprintf("Query parameter '%s' is missing", name)
				return "", weberrors.New(httpStatusForSecurityFailure, msg)
			}
			return value, nil
		case openapi3.ParameterInHeader:
			values := state.Request().Header[http.CanonicalHeaderKey(name)]
			if len(values) == 0 {
				msg := fmt.Sprintf("HTTP header '%s' is missing", name)
				return "", weberrors.New(httpStatusForSecurityFailure, msg)
			}
			return values[0], nil
		default:
			return "", fmt.Errorf("Invalid security scheme 'in' value '%s'", in)
		}
	case "http":
		switch securityScheme.Scheme {
		case "basic":
			return getHTTPBasicToken(state.Request())
		case "bearer":
			return getHTTPBearerToken(state.Request())
		default:
			return "", fmt.Errorf("Security scheme of type 'http' doesn't support scheme '%v'", securityScheme.Scheme)
		}
	default:
		return "", fmt.Errorf("Security scheme type must be 'apiKey' or 'http'")
	}
}

func SetWWWAuthenticateHeader(header http.Header, realm string) {
	headerValue := "Basic"
	if len(realm) > 0 {
		headerValue = fmt.Sprintf(`Basic realm="%s"` + strings.Replace(realm, `"`, "", -1))
	}
	header.Set("WWW-Authenticate", headerValue)
}

func getHTTPBasicToken(req *http.Request) (string, error) {
	// Get "Authorization" header
	value := req.Header.Get("Authorization")
	if len(value) == 0 {
		return "", ErrAuthorizationHeaderMissing
	}

	// Remove "Basic " prefix
	prefix := "Basic "
	if strings.HasPrefix(value, prefix) == false {
		return "", ErrAuthorizationHeaderNotBasic
	}
	value = value[len(prefix):]

	// Decode username:password
	data, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return "", ErrAuthorizationHeaderNotValidBasic
	}
	return string(data), nil
}

func getHTTPBearerToken(req *http.Request) (string, error) {
	// Get "Authorization" header
	value := req.Header.Get("Authorization")
	if len(value) == 0 {
		return "", ErrAuthorizationHeaderMissing
	}

	// Remove "Bearer " prefix
	prefix := "Bearer "
	if strings.HasPrefix(value, prefix) == false {
		return "", ErrAuthorizationHeaderNotBearer
	}
	value = value[len(prefix):]
	return value, nil
}
