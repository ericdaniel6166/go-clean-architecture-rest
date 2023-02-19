package utils

import (
	"context"
	"github.com/labstack/echo/v4"
)

// GetConfigPath Get config path for local or docker
func GetConfigPath(configPath string) string {
	if configPath == "docker" {
		return "./config/config-docker"
	}
	return "./config/config-local"
}

// ReadRequest Read request body and validate
func ReadRequest(ctx echo.Context, request interface{}) error {
	if err := ctx.Bind(request); err != nil {
		return err
	}
	return validate.StructCtx(ctx.Request().Context(), request)
}

//// LogResponseError Error response with logging error for echo context
//func LogResponseError(ctx echo.Context, logger logger.Logger, err error) {
//	logger.Errorf(
//		"ErrResponseWithLog, RequestID: %s, IPAddress: %s, Error: %s",
//		GetRequestID(ctx),
//		GetIPAddress(ctx),
//		err,
//	)
//}

// GetRequestID Get request id from echo context
func GetRequestID(c echo.Context) string {
	return c.Response().Header().Get(echo.HeaderXRequestID)
}

// ReqIDCtxKey is a key used for the Request ID in context
type ReqIDCtxKey struct{}

// GetRequestCtx Get context  with request id
func GetRequestCtx(c echo.Context) context.Context {
	return context.WithValue(c.Request().Context(), ReqIDCtxKey{}, GetRequestID(c))
}
