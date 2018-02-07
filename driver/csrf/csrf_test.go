package csrf_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jban332/kin-auth"
	"github.com/jban332/kin-auth/driver/csrf"
	"github.com/jban332/kin-openapi/openapi3"
	"github.com/jban332/kin-test/jsontest"
)

func TestCSRF(t *testing.T) {
	c := context.TODO()
	engine := &csrf.Engine{
		CookieConfig: &auth.CookieConfig{
			Name: "Example-Cookie",
		},
		SecurityScheme: &openapi3.SecurityScheme{
			Type: "apiKey",
			In:   openapi3.ParameterInHeader,
			Name: "Example-Header",
		},
	}
	req, _ := http.NewRequest("GET", "https://localhost/", nil)
	state := auth.NewState(nil, req)
	resp := httptest.NewRecorder()
	cookie, err := engine.NewCookie(nil, state)
	if len(cookie.Value) < 16 {
		t.Fatalf("Cookie value is too short")
	}
	if err != nil {
		panic(err)
	}

	// No token
	err = engine.Authenticate(c, state, []string{
		"admin",
	})
	jsontest.ExpectErr(t, err).SomeErr()

	// Only token in header
	req, _ = http.NewRequest("GET", "https://localhost/", nil)
	state = auth.NewState(nil, req)
	resp = httptest.NewRecorder()
	req.Header.Set("Example-Header", cookie.Value)
	err = engine.Authenticate(c, state, []string{
		"admin",
	})
	jsontest.ExpectErr(t, err).SomeErr()

	// Only token in cookies
	req, _ = http.NewRequest("GET", "https://localhost/", nil)
	state = auth.NewState(nil, req)
	resp = httptest.NewRecorder()
	http.SetCookie(resp, cookie)
	err = engine.Authenticate(c, state, []string{
		"admin",
	})
	jsontest.ExpectErr(t, err).SomeErr()

	// OK
	req, _ = http.NewRequest("GET", "https://localhost/", nil)
	state = auth.NewState(nil, req)
	resp = httptest.NewRecorder()
	req.Header.Set("Example-Header", cookie.Value)
	req.AddCookie(cookie)
	err = engine.Authenticate(c, state, []string{
		"admin",
	})
	jsontest.ExpectErr(t, err).Err(nil)
}
