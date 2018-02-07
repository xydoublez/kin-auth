package auth

import "net/http"

var (
	ErrAuthFailed = NewError(http.StatusUnauthorized, "User authentication failed")
)

type AuthenticationError struct {
	httpStatus int
	message    string
	errs       []error
}

func NewError(httpStatus int, message string, errs ...error) error {
	return &AuthenticationError{
		httpStatus: httpStatus,
		message:    message,
		errs:       errs,
	}
}

func (err *AuthenticationError) HTTPStatus() int {
	return err.httpStatus
}

func (err *AuthenticationError) Reasons() []error {
	return err.errs
}

func (err *AuthenticationError) Error() string {
	return err.message
}
