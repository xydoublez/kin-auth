package auth

import (
	"context"
	"net/http"
	"net/url"

	"github.com/jban332/kin-log"
)

var Drivers = make(map[string]func() Driver, 8)

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

// NewState creates a new state.
func NewState(c context.Context, req *http.Request) State {
	queryParams := req.URL.Query()
	return &state{
		request:     req,
		queryParams: queryParams,
	}
}

type state struct {
	request     *http.Request
	queryParams url.Values
}

func (state *state) Request() *http.Request {
	return state.request
}

func (state *state) QueryParams() url.Values {
	return state.queryParams
}
