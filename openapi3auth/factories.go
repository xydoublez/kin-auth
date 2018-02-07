package openapi3auth

import (
	"context"
	"os"

	"github.com/jban332/kin-auth"
	"github.com/jban332/kin-auth/driver/csrf"
	"github.com/jban332/kin-auth/driver/oauth2"
	"github.com/jban332/kin-openapi/openapi3"
)

type FactoryFunc func(c context.Context, securityScheme *openapi3.SecurityScheme) (auth.Driver, error)

var FactoryFuncs = make(map[string]FactoryFunc, 16)

func RegisterFactory(name string, factory FactoryFunc) {
	FactoryFuncs[name] = factory
}

func init() {
	RegisterFactory("csrf", func(c context.Context, securityScheme *openapi3.SecurityScheme) (auth.Driver, error) {
		clone := &openapi3.SecurityScheme{}
		if securityScheme != nil {
			*clone = *securityScheme
		}
		if clone.Type == "" {
			clone.Type = "apiKey"
			clone.In = "header"
			clone.Name = "X-Xsrf-Token"
		}
		engine := &csrf.Engine{
			SecurityScheme: clone,
		}
		return engine, nil
	})
	RegisterFactory("facebook", func(c context.Context, securityScheme *openapi3.SecurityScheme) (auth.Driver, error) {
		engine := &oauth2.Engine{
			ClientID:     os.Getenv("OAUTH2_FACEBOOK_ID"),
			ClientSecret: os.Getenv("OAUTH2_FACEBOOK_SECRET"),
			Flows: &openapi3.OAuthFlows{
				AuthorizationCode: &openapi3.OAuthFlow{
					AuthorizationURL: "https://www.facebook.com/dialog/oauth",
					TokenURL:         "https://graph.facebook.com/oauth/access_token",
					Scopes: map[string]string{
						"public_profile": "",
					},
				},
			},
		}
		if v := os.Getenv("OAUTH2_FACEBOOK_PROOF_SECRET"); len(v) > 0 {
			engine.WithFacebookAppProof(v)
		}
		return engine, nil
	})
	RegisterFactory("github", func(c context.Context, securityScheme *openapi3.SecurityScheme) (auth.Driver, error) {
		engine := &oauth2.Engine{
			ClientID:     os.Getenv("OAUTH2_GITHUB_ID"),
			ClientSecret: os.Getenv("OAUTH2_GITHUB_SECRET"),
			Flows: &openapi3.OAuthFlows{
				AuthorizationCode: &openapi3.OAuthFlow{
					AuthorizationURL: "https://github.com/login/oauth/authorize",
					TokenURL:         "https://github.com/login/oauth/access_token",
					Scopes:           map[string]string{},
				},
			},
		}
		return engine, nil
	})
	RegisterFactory("google", func(c context.Context, securityScheme *openapi3.SecurityScheme) (auth.Driver, error) {
		engine := &oauth2.Engine{
			ClientID:     os.Getenv("OAUTH2_GOOGLE_ID"),
			ClientSecret: os.Getenv("OAUTH2_GOOGLE_SECRET"),
			Flows: &openapi3.OAuthFlows{
				AuthorizationCode: &openapi3.OAuthFlow{
					AuthorizationURL: "https://accounts.google.com/o/oauth2/auth?access_type=offline",
					TokenURL:         "https://accounts.google.com/o/oauth2/token",
					Scopes:           map[string]string{},
				},
			},
		}
		return engine, nil
	})
	RegisterFactory("twitter", func(c context.Context, securityScheme *openapi3.SecurityScheme) (auth.Driver, error) {
		engine := &oauth2.Engine{
			ClientID:     os.Getenv("OAUTH2_TWITTER_ID"),
			ClientSecret: os.Getenv("OAUTH2_TWITTER_SECRET"),
			Flows: &openapi3.OAuthFlows{
				AuthorizationCode: &openapi3.OAuthFlow{
					AuthorizationURL: "https://api.twitter.com/oauth/authorize",
					TokenURL:         "https://api.twitter.com/oauth/access_token",
					Scopes:           map[string]string{},
				},
			},
		}
		return engine, nil
	})
}
