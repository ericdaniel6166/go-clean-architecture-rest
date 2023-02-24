package middlewares

import (
	"github.com/labstack/echo/v4"
	"go-clean-architecture-rest/internal/models"
	"go-clean-architecture-rest/pkg/csrf"
	"go-clean-architecture-rest/pkg/httpErrors"
	"go-clean-architecture-rest/pkg/utils"
	"net/http"
)

// CSRF Middleware
func (mw *MiddlewareManager) CSRF(next echo.HandlerFunc) echo.HandlerFunc {
	return func(ctx echo.Context) error {
		if !mw.cfg.Server.CSRF {
			return next(ctx)
		}

		token := ctx.Request().Header.Get(csrf.CSRFHeader)
		if token == "" {
			mw.logger.Errorf("CSRF Middleware get CSRF header, Token: %s, Error: %s, RequestId: %s",
				token,
				"empty CSRF token",
				utils.GetRequestID(ctx),
			)
			return ctx.JSON(http.StatusForbidden, httpErrors.NewRestError(http.StatusForbidden, "Invalid CSRF Token", "no CSRF Token"))
		}

		//sid, ok := ctx.Get("sid").(string)
		//if !csrf.ValidateToken(token, sid, mw.logger) || !ok {
		user, ok := ctx.Get("user").(*models.User)
		if !csrf.ValidateToken(token, user.UserID.String(), mw.logger) || !ok {
			mw.logger.Errorf("CSRF Middleware csrf.ValidateToken Token: %s, Error: %s, RequestId: %s",
				token,
				"invalid CSRF token",
				utils.GetRequestID(ctx),
			)
			return ctx.JSON(http.StatusForbidden, httpErrors.NewRestError(http.StatusForbidden, "Invalid CSRF Token", "invalid CSRF Token"))
		}

		return next(ctx)
	}
}
