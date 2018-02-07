package gae_test

import (
	"context"
	"testing"

	"github.com/jban332/kin-auth"
	"github.com/jban332/kin-auth/driver/gae"
	"github.com/jban332/kin-test/jsontest"
	"google.golang.org/appengine"
	"google.golang.org/appengine/aetest"
	"google.golang.org/appengine/user"
)

func TestGae(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping the test because of -short")
		return
	}

	// New server instance
	instance, err := aetest.NewInstance(nil)
	defer instance.Close()
	if err != nil {
		panic(err)
	}
	engine := &gae.Engine{}

	newContext := func(u *user.User) (context.Context, auth.State) {
		req, err := instance.NewRequest("GET", "/", nil)
		if err != nil {
			panic(err)
		}
		c := req.Context()
		c = appengine.WithContext(c, req)
		if u != nil {
			aetest.Login(u, req)
			t.Logf("Logged in as '%s'", u.Email)
		}
		return c, auth.NewState(c, req)
	}

	// No user
	{
		c, state := newContext(nil)
		err = engine.Authenticate(c, state, nil)
		jsontest.ExpectErr(t, err).SomeErr()
	}

	// Logged-in
	{
		c, state := newContext(&user.User{
			ID:    "someUser",
			Email: "user@example.com",
		})
		err = engine.Authenticate(c,
			state,
			nil)
		jsontest.ExpectErr(t, err).Err(nil)
	}

	// No admin
	{
		c, state := newContext(&user.User{
			ID:    "someUser",
			Email: "user@example.com",
		})
		err = engine.Authenticate(c,
			state,
			[]string{
				"admin",
			})
		jsontest.ExpectErr(t, err).SomeErr()
	}

	// Admin
	{
		c, state := newContext(&user.User{
			Admin: true,
			ID:    "someUser",
			Email: "user@example.com",
		})
		err = engine.Authenticate(c,
			state,
			[]string{
				"admin",
			})
		jsontest.ExpectErr(t, err).Err(nil)
	}

}
