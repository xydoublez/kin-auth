package session_test

import (
	"net/http"
	"testing"

	"github.com/jban332/kin-auth"
	"github.com/jban332/kin-auth/driver/session"
	"github.com/jban332/kin-auth/jwt"
	"github.com/jban332/kin-test/webtest"
)

func TestSession(t *testing.T) {
	createdSession := &session.Session{
		UserID:    "exampleUser",
		SessionID: "exampleSession",
	}
	engine := &session.Engine{
		JWT: jwt.NewConfig(""),
	}
	app := http.NewServeMux()
	app.HandleFunc("/login", func(resp http.ResponseWriter, req *http.Request) {
		c := req.Context()
		state := auth.NewState(c, req)
		cookie, err := engine.NewCookie(c, state, createdSession)
		if err != nil {
			panic(err)
		}
		http.SetCookie(resp, cookie)
		resp.WriteHeader(200)
	})
	app.HandleFunc("/test", func(resp http.ResponseWriter, req *http.Request) {
		receivedSession, err := engine.ReadCookie(nil, req)
		if err != nil {
			t.Fatalf("GetSession failed: %v", err)
		}
		if receivedSession.UserID != createdSession.UserID {
			t.Fatalf("Expected userId '%v', actually '%v'", createdSession.UserID, receivedSession.UserID)
		}
		if receivedSession.SessionID != createdSession.SessionID {
			t.Fatalf("Expected sessionId '%v', actually '%v'", createdSession.SessionID, receivedSession.SessionID)
		}
		resp.WriteHeader(200)
	})

	client := webtest.NewClient(t)
	client.AddHostHandler("localhost", app)
	// Test login
	{
		resp := client.Request("GET", "https://localhost/login").Send()
		resp.ExpectCookieReceived(engine.GetCookieConfig().Name, true)
	}
	// Test session
	{
		client.Request("GET", "https://localhost//test").Send()
	}
}
