package csrf_test

import (
	"context"
	"github.com/jban332/kin-openapi/openapi3"
	"github.com/jban332/kin/core/jsontest"
	"github.com/jban332/kin/core/kincontext"
	"github.com/jban332/kin/service/auth"
	"github.com/jban332/kin/service/auth/driver/csrf"
	"testing"
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
	task := kincontext.NewFakeTask("GET", "https://localhost/", nil)
	cookie, err := engine.NewCookie(nil, task)
	if len(cookie.Value) < 16 {
		t.Fatalf("Cookie value is too short")
	}
	if err != nil {
		panic(err)
	}

	// No token
	err = engine.Authenticate(c, task, []string{
		"admin",
	})
	jsontest.ExpectErr(t, err).SomeErr()

	// Only token in header
	task = kincontext.NewFakeTask("GET", "https://localhost/", nil)
	task.Request().Header.Set("Example-Header", cookie.Value)
	err = engine.Authenticate(c, task, []string{
		"admin",
	})
	jsontest.ExpectErr(t, err).SomeErr()

	// Only token in cookies
	task = kincontext.NewFakeTask("GET", "https://localhost/", nil)
	task.Request().AddCookie(cookie)
	err = engine.Authenticate(c, task, []string{
		"admin",
	})
	jsontest.ExpectErr(t, err).SomeErr()

	// OK
	task = kincontext.NewFakeTask("GET", "https://localhost/", nil)
	task.Request().Header.Set("Example-Header", cookie.Value)
	task.Request().AddCookie(cookie)
	err = engine.Authenticate(c, task, []string{
		"admin",
	})
	jsontest.ExpectErr(t, err).Err(nil)
}
