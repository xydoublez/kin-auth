package apikey_test

import (
	"context"
	"net/http"
	"testing"

	auth "github.com/jban332/kin-auth"
	"github.com/jban332/kin-auth/driver/apikey"
	"github.com/jban332/kin-openapi/openapi3"
	"github.com/jban332/kin-test/jsontest"
)

func TestAPIKey(t *testing.T) {
	c := context.TODO()
	engine := &apikey.Engine{
		SecurityScheme: &openapi3.SecurityScheme{
			Type: "apiKey",
			In:   openapi3.ParameterInHeader,
			Name: "X-API-Key", // Keep in non-canonical form
		},
		KeyValidatorFunc: func(c context.Context, input *apikey.ValidationInput) error {
			if input.APIKey == "qwerty" {
				return nil
			}
			return apikey.ErrAPIKeyNotCorrect
		},
	}
	req, _ := http.NewRequest("GET", "/", nil)
	state := auth.NewState(nil, req)
	var err error

	// No value at all
	err = engine.Authenticate(c, state, []string{
		"admin",
	})
	jsontest.ExpectErr(t, err).ErrString("HTTP header 'X-API-Key' is missing")

	// Wrong value
	req.Header.Set("X-API-Key", "wrong")
	err = engine.Authenticate(c, state, []string{
		"admin",
	})
	jsontest.ExpectErr(t, err).Err(apikey.ErrAPIKeyNotCorrect)

	// Correct value
	req.Header.Set("X-API-Key", "qwerty")
	err = engine.Authenticate(c, state, []string{
		"admin",
	})
	jsontest.ExpectErr(t, err).Err(nil)
}

func TestHTTPBearer(t *testing.T) {
	c := context.TODO()
	engine := &apikey.Engine{
		SecurityScheme: &openapi3.SecurityScheme{
			Type:   "http",
			Scheme: "bearer",
		},
		KeyValidatorFunc: func(c context.Context, input *apikey.ValidationInput) error {
			if input.APIKey == "qwerty" {
				return nil
			}
			return apikey.ErrAPIKeyNotCorrect
		},
	}
	req, _ := http.NewRequest("GET", "/", nil)
	state := auth.NewState(nil, req)
	header := req.Header
	var err error

	// No value at all
	err = engine.Authenticate(c, state, []string{
		"admin",
	})
	jsontest.ExpectErr(t, err).Err(apikey.ErrAuthorizationHeaderMissing)

	// Wrong value
	header.Set("Authorization", "Bearer wrong")
	err = engine.Authenticate(c, state, []string{
		"admin",
	})
	jsontest.ExpectErr(t, err).Err(apikey.ErrAPIKeyNotCorrect)

	// Correct value
	header.Set("Authorization", "Bearer qwerty")
	err = engine.Authenticate(c, state, []string{
		"admin",
	})
	jsontest.ExpectErr(t, err).Err(nil)
}

func TestHTTPBasic(t *testing.T) {
	c := context.TODO()
	engine := &apikey.Engine{
		SecurityScheme: &openapi3.SecurityScheme{
			Type:   "http",
			Scheme: "basic",
		},
		KeyValidatorFunc: func(c context.Context, input *apikey.ValidationInput) error {
			if input.APIKey == "adam:qwerty" {
				return nil
			}
			return apikey.ErrAPIKeyNotCorrect
		},
	}
	req, _ := http.NewRequest("GET", "/", nil)
	state := auth.NewState(nil, req)
	var err error

	// No value at all
	err = engine.Authenticate(c, state, []string{
		"admin",
	})
	jsontest.ExpectErr(t, err).Err(apikey.ErrAuthorizationHeaderMissing)

	// Wrong value
	req.SetBasicAuth("adam", "wrong")
	err = engine.Authenticate(c, state, []string{
		"admin",
	})
	jsontest.ExpectErr(t, err).Err(apikey.ErrAPIKeyNotCorrect)

	// Correct value
	req.SetBasicAuth("adam", "qwerty")
	err = engine.Authenticate(c, state, []string{
		"admin",
	})
	jsontest.ExpectErr(t, err).Err(nil)
}
