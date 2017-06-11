package gae_test

import (
	"context"
	"github.com/jban332/kincore/jsontest"
	"github.com/jban332/kincore/kincontext"
	"github.com/jban332/kinauth/driver/gae"
	"google.golang.org/appengine"
	"google.golang.org/appengine/aetest"
	"google.golang.org/appengine/user"
	"testing"
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

	newContext := func(u *user.User) (context.Context, kincontext.Task) {
		req, err := instance.NewRequest("GET", "/", nil)
		if err != nil {
			panic(err)
		}
		c := kincontext.NewContext(nil, req)
		c = appengine.WithContext(c, req)
		task := kincontext.NewTask(nil, req)
		if u != nil {
			aetest.Login(u, req)
			t.Logf("Logged in as '%s'", u.Email)
		}
		return c, task
	}

	// No user
	{
		c, task := newContext(nil)
		err = engine.Authenticate(c,
			task,
			nil)
		jsontest.ExpectErr(t, err).SomeErr()
	}

	// Logged-in
	{
		c, task := newContext(&user.User{
			ID:    "someUser",
			Email: "user@example.com",
		})
		err = engine.Authenticate(c,
			task,
			nil)
		jsontest.ExpectErr(t, err).Err(nil)
	}

	// No admin
	{
		c, task := newContext(&user.User{
			ID:    "someUser",
			Email: "user@example.com",
		})
		err = engine.Authenticate(c,
			task,
			[]string{
				"admin",
			})
		jsontest.ExpectErr(t, err).SomeErr()
	}

	// Admin
	{
		c, task := newContext(&user.User{
			Admin: true,
			ID:    "someUser",
			Email: "user@example.com",
		})
		err = engine.Authenticate(c,
			task,
			[]string{
				"admin",
			})
		jsontest.ExpectErr(t, err).Err(nil)
	}

}
