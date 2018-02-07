package gae

import (
	"context"

	"github.com/jban332/kin-auth"
	"github.com/jban332/kin-auth/openapi3auth"
	"github.com/jban332/kin-openapi/openapi3"
	gaeuser "google.golang.org/appengine/user"
)

func init() {
	// IMPORTANT: This is an abuse of OpenAPI3 specification.
	//
	// In practice this should be ok.
	openapi3auth.RegisterFactory("gae", func(c context.Context, securityScheme *openapi3.SecurityScheme) (auth.Driver, error) {
		return &Engine{}, nil
	})
}

var (
	_ auth.Driver          = &Engine{}
	_ auth.LoginURLDriver  = &Engine{}
	_ auth.LogoutURLDriver = &Engine{}
)

type Engine struct{}

func (engine *Engine) Authenticate(c context.Context, state auth.State, scopes []string) error {
	u := gaeuser.Current(c)
	if u == nil || u.Email == "" {
		return auth.ErrAuthFailed
	}
	for _, scope := range scopes {
		switch scope {
		case "admin":
			if u.Admin == false {
				return auth.ErrAuthFailed
			}
		default:
			return auth.ErrAuthFailed
		}
	}
	return nil
}

func (engine *Engine) LoginURL(c context.Context, scopes []string, callbackURL string) (string, error) {
	url, err := gaeuser.LoginURL(c, callbackURL)
	if err != nil {
		return "", err
	}
	return url, nil
}

func (engine *Engine) LogoutURL(c context.Context, callbackURL string) (string, error) {
	url, err := gaeuser.LogoutURL(c, callbackURL)
	if err != nil {
		return "", err
	}
	return url, nil
}
