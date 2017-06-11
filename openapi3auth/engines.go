package openapi3auth

import (
	"context"
	"github.com/jban332/kin-openapi/openapi3"
	"github.com/jban332/kin/service/auth"
	"github.com/jban332/kin/service/log"
	"net/http"
)

const httpStatusForSecurityFailure = http.StatusUnauthorized

func NewEngine(c context.Context, name string, securityScheme *openapi3.SecurityScheme) (auth.Driver, error) {
	factory := FactoryFuncs[name]
	if factory == nil {
		return nil, nil
	}
	return factory(c, securityScheme)
}

func PutEnginesInSwagger(c context.Context, engines Engines, swagger *openapi3.Swagger) error {
	if securitySchemes := swagger.Components.SecuritySchemes; securitySchemes != nil {
		for name, securityScheme := range securitySchemes {
			engine, err := NewEngine(c, name, securityScheme)
			if err != nil {
				return err
			}
			if engine == nil {
				auth.Logger.WarningC(c, "Security engine was not found",
					log.String("name", name))
			} else {
				engines[name] = engine
			}
		}
	}
	return nil
}

type Engines map[string]auth.Driver