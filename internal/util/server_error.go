package util

import (
	"fmt"
	"net/http"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

type WrappedServerError struct {
	internal error
	id       string
}

func (e WrappedServerError) Error() string {
	return e.internal.Error()
}

func (e WrappedServerError) Unwrap() error {
	return e.internal
}

func (e WrappedServerError) ID() string {
	return e.id
}

func ServerError(message string, internal error) *echo.HTTPError {
	wrapped := WrappedServerError{
		internal: internal,
		id:       uuid.NewString(),
	}

	return echo.NewHTTPError(http.StatusInternalServerError, fmt.Sprintf("%s (error id %s)", message, wrapped.id)).SetInternal(wrapped)
}

func GenericServerErr(internal error) *echo.HTTPError {
	return ServerError("internal server error", internal)
}
