package jwt

import (
	"net/http"

	"github.com/jban332/kin-auth"
)

var ErrTooLarge = auth.NewError(http.StatusBadRequest, "JWT value is too large")

// ErrParsing is returned if the JWT token can't be split by dots.
var ErrParsing = auth.NewError(http.StatusBadRequest, "JWT parsing failed")

// ErrHeaderParsing is returned if the JWT header can't be parsed.
var ErrHeaderParsing = auth.NewError(http.StatusBadRequest, "JWT header parsing failed")

// ErrHeaderType is returned if the JWT header has an unsupported type.
var ErrHeaderType = auth.NewError(http.StatusBadRequest, "JWT header type is unsupported")

// ErrHeaderAlgorithm is returned if the JWT header has an unsupported algorithm.
var ErrHeaderAlgorithm = auth.NewError(http.StatusBadRequest, "JWT header algorithm is unsupported")

// ErrSignatureParsing is returned if the JWT signature can't be parsed.
var ErrSignatureParsing = auth.NewError(http.StatusBadRequest, "JWT signature is not valid base64")

// ErrSignatureValue is returned if the JWT signature is wrong.
var ErrSignatureValue = auth.NewError(http.StatusBadRequest, "JWT signature is incorrect")

// ErrMissingExpiration is returned by CheckNotExpired if the 'exp' field is missing
var ErrMissingExpiration = auth.NewError(http.StatusBadRequest, "JWT value doesn't have expiration")

// ErrExpired is returned by CheckNotExpired if the 'exp' field has expired
var ErrExpired = auth.NewError(http.StatusBadRequest, "JWT value has expired")
