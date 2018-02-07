package oauth2

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/jban332/go-httphelpers/webclient"
	"github.com/jban332/kin-auth"
	"github.com/jban332/kin-log"
	"github.com/jban332/kin-openapi/openapi3"
	"golang.org/x/oauth2"
)

const httpStatusForSecurityFailure = http.StatusUnauthorized

// OAuth2 errors
var (
	ErrFlowMissing                  = auth.NewError(httpStatusForSecurityFailure, "OAuth2 security scheme does not have 'authorizationCode' flow.")
	ErrAuthorizationHeaderMissing   = auth.NewError(httpStatusForSecurityFailure, "OAuth2 failed because header 'Authorization' is missing")
	ErrAuthorizationHeaderNotBearer = auth.NewError(httpStatusForSecurityFailure, "OAuth2 failed because header 'Authorization' does not have prefix 'Bearer '")
	ErrExchangeFailed               = auth.NewError(httpStatusForSecurityFailure, "OAuth2 exchange with the identity provider failed")
)

type Engine struct {
	ClientFactory func(c context.Context) *http.Client
	ExchangeFunc  func(c context.Context, config *oauth2.Config, code string) (*oauth2.Token, error)

	ClientID     string               `json:"clientId,omitempty"`
	ClientSecret string               `json:"-"` // Prevent accidental leaks by not serializing the field
	Flows        *openapi3.OAuthFlows `json:"security,omitempty"`
}

func (engine *Engine) WithFacebookAppProof(secret string) *Engine {
	oldExchageFunc := engine.ExchangeFunc
	engine.ExchangeFunc = func(c context.Context, config *oauth2.Config, code string) (*oauth2.Token, error) {
		hash := hmac.New(sha256.New, []byte(secret))
		hash.Write([]byte(config.ClientSecret))
		signature := hex.EncodeToString(hash.Sum(nil))
		tokenURL, err := webclient.RawURLWithQueryParam(
			config.Endpoint.TokenURL,
			"appsecret_proof",
			signature)
		if err != nil {
			return nil, fmt.Errorf("TokenURL is not valid URL: %v", err)
		}
		config.Endpoint.TokenURL = tokenURL
		if oldExchageFunc != nil {
			return oldExchageFunc(c, config, code)
		}
		return config.Exchange(c, code)
	}
	return engine
}

func (engine *Engine) Authenticate(c context.Context, state auth.State, scopes []string) error {
	flows := engine.Flows
	if flows == nil {
		return ErrFlowMissing
	}
	flow := flows.AuthorizationCode
	if flow == nil {
		return ErrFlowMissing
	}
	code, err := engine.getCode(state)
	if err != nil {
		return err
	}
	token, err := engine.ExchangeCode(c, code, flow, scopes)
	if err != nil || token == nil {
		return ErrExchangeFailed
	}
	return nil
}

func (engine *Engine) getCode(state auth.State) (string, error) {
	value := state.Request().Header.Get("Authorization")
	if value == "" {
		return "", ErrAuthorizationHeaderMissing
	}
	const bearerPrefix = "Bearer "
	if !strings.HasPrefix(value, bearerPrefix) {
		return "", ErrAuthorizationHeaderNotBearer
	}
	value = value[len(bearerPrefix):]
	return value, nil
}

func (engine *Engine) ExchangeCode(c context.Context, code string, flow *openapi3.OAuthFlow,
	scopes []string) (*oauth2.Token, error) {
	config, err := engine.configForFlow(flow, scopes)
	if err != nil {
		auth.Logger.InfoC(c, "OAuth2 exchange failed because of missing flow", log.Err(err))
		return nil, err
	}
	f := engine.ClientFactory
	if f == nil {
		f = webclient.NewHTTPClient
	}
	client := f(c)
	c = context.WithValue(c, oauth2.HTTPClient, client)
	var token *oauth2.Token
	if f := engine.ExchangeFunc; f != nil {
		token, err = f(c, config, code)
	} else {
		token, err = config.Exchange(c, code)
	}
	if err != nil {
		auth.Logger.InfoC(c, "OAuth2 exchange failed", log.Err(err))
		return nil, err
	}
	if !token.Valid() {
		auth.Logger.InfoC(c, "OAuth2 exchange failed because token received from the provider is not valid")
		return nil, errors.New("Received OAuth2 token is not valid")
	}
	return token, nil
}

func (engine *Engine) configForFlow(flow *openapi3.OAuthFlow, scopes []string) (*oauth2.Config, error) {
	clientID := engine.ClientID
	clientSecret := engine.ClientSecret
	config := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  flow.AuthorizationURL,
			TokenURL: flow.TokenURL,
		},
		Scopes: scopes,
	}
	return config, nil
}
