package auth

import (
	"context"
	"github.com/jban332/kin/core/jwt"
	"github.com/jban332/kin-openapi/jsoninfo"
)

// JWTConfig is a helper type for security engines that use JWT
type JWTConfig struct {
	Secret string `json:"-"` // Prevent accidental leaks by not serializing the field
}

func (value *JWTConfig) MarshalJSON() ([]byte, error) {
	return jsoninfo.MarshalStructFields(value)
}

func (value *JWTConfig) UnmarshalJSON(data []byte) error {
	return jsoninfo.UnmarshalStructFields(data, value)
}

func (jwtConfig *JWTConfig) DecodeString(c context.Context, value string) ([]byte, error) {
	secret := jwtConfig.Secret
	return jwt.NewConfig(secret).DecodeString(c, value)
}

func (jwtConfig *JWTConfig) EncodeToString(c context.Context, value []byte) (string, error) {
	secret := jwtConfig.Secret
	return jwt.NewConfig(secret).EncodeToString(c, value), nil
}
