package auth

import (
	"context"
	"github.com/jban332/kincore/kincontext"
	"github.com/jban332/kincore/weberrors"
	"github.com/jban332/kinlog"
	"net/http"
	"net/url"
)

var Drivers = make(map[string]func() Driver, 8)

var ErrAuthFailed = weberrors.New(http.StatusUnauthorized, "User authentication failed")

var Logger = log.NewLogger().WithPrefix("auth: ")

type Driver interface {
	Authenticate(c context.Context, state State, scopes []string) error
}

type LoginURLDriver interface {
	LoginURL(c context.Context, scopes []string, callbackURL string) (string, error)
}

type LogoutURLDriver interface {
	LogoutURL(c context.Context, callbackURL string) (string, error)
}

type State interface {
	Request() *http.Request
	QueryParams() url.Values
}

func NewState(c context.Context, req *http.Request) State {
	return kincontext.NewTask(nil, req)
}
