package apikey_test

import (
	"context"
	"github.com/jban332/kin-openapi/openapi3"
	"github.com/jban332/kincore/jsontest"
	"github.com/jban332/kincore/kincontext"
	"github.com/jban332/kinauth/driver/apikey"
	"testing"
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
	task := kincontext.NewFakeTask("GET", "/", nil)
	header := task.Request().Header
	var err error

	// No value at all
	err = engine.Authenticate(c, task, []string{
		"admin",
	})
	jsontest.ExpectErr(t, err).ErrString("HTTP header 'X-API-Key' is missing")

	// Wrong value
	header.Set("X-API-Key", "wrong")
	err = engine.Authenticate(c, task, []string{
		"admin",
	})
	jsontest.ExpectErr(t, err).Err(apikey.ErrAPIKeyNotCorrect)

	// Correct value
	header.Set("X-API-Key", "qwerty")
	err = engine.Authenticate(c, task, []string{
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
	task := kincontext.NewFakeTask("GET", "/", nil)
	header := task.Request().Header
	var err error

	// No value at all
	err = engine.Authenticate(c, task, []string{
		"admin",
	})
	jsontest.ExpectErr(t, err).Err(apikey.ErrAuthorizationHeaderMissing)

	// Wrong value
	header.Set("Authorization", "Bearer wrong")
	err = engine.Authenticate(c, task, []string{
		"admin",
	})
	jsontest.ExpectErr(t, err).Err(apikey.ErrAPIKeyNotCorrect)

	// Correct value
	header.Set("Authorization", "Bearer qwerty")
	err = engine.Authenticate(c, task, []string{
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
	task := kincontext.NewFakeTask("GET", "/", nil)
	req := task.Request()
	var err error

	// No value at all
	err = engine.Authenticate(c, task, []string{
		"admin",
	})
	jsontest.ExpectErr(t, err).Err(apikey.ErrAuthorizationHeaderMissing)

	// Wrong value
	req.SetBasicAuth("adam", "wrong")
	err = engine.Authenticate(c, task, []string{
		"admin",
	})
	jsontest.ExpectErr(t, err).Err(apikey.ErrAPIKeyNotCorrect)

	// Correct value
	req.SetBasicAuth("adam", "qwerty")
	err = engine.Authenticate(c, task, []string{
		"admin",
	})
	jsontest.ExpectErr(t, err).Err(nil)
}
