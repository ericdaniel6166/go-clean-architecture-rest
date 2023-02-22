package middlewares

import (
	"context"
	"fmt"
	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"go-clean-architecture-rest/config"
	"go-clean-architecture-rest/internal/auth"
	"go-clean-architecture-rest/pkg/httpErrors"
	"go-clean-architecture-rest/pkg/utils"
	"go.uber.org/zap"
	"net/http"
	"strings"
)

// AuthSessionMiddleware Auth sessions middleware using redis
func (mw *MiddlewareManager) AuthSessionMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		cookie, err := c.Cookie(mw.cfg.Session.Name)
		mw.logger.Infof("cookie name: %s, cookie: %#v", mw.cfg.Session.Name, cookie)
		if err != nil {
			mw.logger.Errorf("AuthSessionMiddleware RequestID: %s, Error: %s",
				utils.GetRequestID(c),
				err.Error(),
			)
			if err == http.ErrNoCookie {
				return c.JSON(http.StatusUnauthorized, httpErrors.NewUnauthorizedError(err))
			}
			return c.JSON(http.StatusUnauthorized, httpErrors.NewUnauthorizedError(httpErrors.Unauthorized))
		}

		sid := cookie.Value
		mw.logger.Infof("sid: %s", sid)

		sess, err := mw.sessUC.GetSessionByID(c.Request().Context(), cookie.Value)
		mw.logger.Infof("sess.SessionID: %s", sess.SessionID)
		if err != nil {
			mw.logger.Errorf("GetSessionByID RequestID: %s, CookieValue: %s, Error: %s",
				utils.GetRequestID(c),
				cookie.Value,
				err.Error(),
			)
			return c.JSON(http.StatusUnauthorized, httpErrors.NewUnauthorizedError(httpErrors.Unauthorized))
		}

		user, err := mw.authUC.GetByID(c.Request().Context(), sess.UserID)
		if err != nil {
			mw.logger.Errorf("GetByID RequestID: %s, Error: %s",
				utils.GetRequestID(c),
				err.Error(),
			)
			return c.JSON(http.StatusUnauthorized, httpErrors.NewUnauthorizedError(httpErrors.Unauthorized))
		}

		c.Set("sid", sid)
		mw.logger.Infof("set cookie.Value to sid in the context, sid: %s", sid)
		c.Set("uid", sess.SessionID)
		mw.logger.Infof("set sess.SessionID to uid in the context, uid: %s", sess.SessionID)
		c.Set("user", user)
		mw.logger.Infof("save user in the context, user.UserID: %s, user.Email: %s", user.UserID.String(), user.Email)

		ctx := context.WithValue(c.Request().Context(), utils.UserCtxKey{}, user)
		c.SetRequest(c.Request().WithContext(ctx))

		mw.logger.Infof(
			"SessionMiddleware, RequestID: %s,  IP: %s, UserID: %s, CookieSessionID: %s, cookie.Value: %s, uid: %s, sess.SessionID: %s",
			utils.GetRequestID(c),
			utils.GetIPAddress(c),
			user.UserID.String(),
			cookie.Value,
			cookie.Value,
			sess.SessionID,
			sess.SessionID,
		)

		return next(c)
	}
}

// AuthJWTMiddleware JWT way of auth using cookie or Authorization header
func (mw *MiddlewareManager) AuthJWTMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		bearerHeader := c.Request().Header.Get("Authorization")

		mw.logger.Infof("AuthJWTMiddleware, bearerHeader: %s", bearerHeader)

		if bearerHeader != "" {
			headerParts := strings.Split(bearerHeader, " ")
			if len(headerParts) != 2 {
				mw.logger.Error("auth middleware", zap.String("headerParts", "len(headerParts) != 2"))
				return c.JSON(http.StatusUnauthorized, httpErrors.NewUnauthorizedError(httpErrors.Unauthorized))
			}
			mw.logger.Infof("auth middleware headerParts: %s", headerParts)

			tokenString := headerParts[1]

			if err := mw.validateJWTToken(tokenString, mw.authUC, c, mw.cfg); err != nil {
				mw.logger.Error("middleware validateJWTToken", zap.String("headerJWT", err.Error()))
				return c.JSON(http.StatusUnauthorized, httpErrors.NewUnauthorizedError(httpErrors.Unauthorized))
			}

			return next(c)
		}

		cookie, err := c.Cookie("jwt-token")
		if err != nil {
			mw.logger.Errorf("c.Cookie", err.Error())
			return c.JSON(http.StatusUnauthorized, httpErrors.NewUnauthorizedError(httpErrors.Unauthorized))
		}

		if err = mw.validateJWTToken(cookie.Value, mw.authUC, c, mw.cfg); err != nil {
			mw.logger.Errorf("validateJWTToken", err.Error())
			return c.JSON(http.StatusUnauthorized, httpErrors.NewUnauthorizedError(httpErrors.Unauthorized))
		}
		return next(c)
	}
}

//// AuthJWTMiddleware JWT way of auth using cookie or Authorization header
//func (mw *MiddlewareManager) AuthJWTMiddleware(authUC auth.UseCase, cfg *config.Config) echo.MiddlewareFunc {
//	return func(next echo.HandlerFunc) echo.HandlerFunc {
//		return func(c echo.Context) error {
//			bearerHeader := c.Request().Header.Get("Authorization")
//
//			mw.logger.Infof("auth middleware bearerHeader %s", bearerHeader)
//
//			if bearerHeader != "" {
//				headerParts := strings.Split(bearerHeader, " ")
//				if len(headerParts) != 2 {
//					mw.logger.Error("auth middleware", zap.String("headerParts", "len(headerParts) != 2"))
//					return c.JSON(http.StatusUnauthorized, httpErrors.NewUnauthorizedError(httpErrors.Unauthorized))
//				}
//
//				tokenString := headerParts[1]
//
//				if err := mw.validateJWTToken(tokenString, authUC, c, cfg); err != nil {
//					mw.logger.Error("middleware validateJWTToken", zap.String("headerJWT", err.Error()))
//					return c.JSON(http.StatusUnauthorized, httpErrors.NewUnauthorizedError(httpErrors.Unauthorized))
//				}
//
//				return next(c)
//			}
//
//			cookie, err := c.Cookie("jwt-token")
//			if err != nil {
//				mw.logger.Errorf("c.Cookie", err.Error())
//				return c.JSON(http.StatusUnauthorized, httpErrors.NewUnauthorizedError(httpErrors.Unauthorized))
//			}
//
//			if err = mw.validateJWTToken(cookie.Value, authUC, c, cfg); err != nil {
//				mw.logger.Errorf("validateJWTToken", err.Error())
//				return c.JSON(http.StatusUnauthorized, httpErrors.NewUnauthorizedError(httpErrors.Unauthorized))
//			}
//			return next(c)
//		}
//	}
//}

//// Admin role
//func (mw *MiddlewareManager) AdminMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
//	return func(c echo.Context) error {
//		user, ok := c.Get("user").(*models.User)
//		if !ok || *user.Role != "admin" {
//			return c.JSON(http.StatusForbidden, httpErrors.NewUnauthorizedError(httpErrors.PermissionDenied))
//		}
//		return next(c)
//	}
//}

//// Role based auth middleware, using ctx user
//func (mw *MiddlewareManager) OwnerOrAdminMiddleware() echo.MiddlewareFunc {
//	return func(next echo.HandlerFunc) echo.HandlerFunc {
//		return func(c echo.Context) error {
//			user, ok := c.Get("user").(*models.User)
//			if !ok {
//				mw.logger.Errorf("Error c.Get(user) RequestID: %s, ERROR: %s,", utils.GetRequestID(c), "invalid user ctx")
//				return c.JSON(http.StatusUnauthorized, httpErrors.NewUnauthorizedError(httpErrors.Unauthorized))
//			}
//
//			if *user.Role == "admin" {
//				return next(c)
//			}
//
//			if user.UserID.String() != c.Param("user_id") {
//				mw.logger.Errorf("Error c.Get(user) RequestID: %s, UserID: %s, ERROR: %s,",
//					utils.GetRequestID(c),
//					user.UserID.String(),
//					"invalid user ctx",
//				)
//				return c.JSON(http.StatusForbidden, httpErrors.NewForbiddenError(httpErrors.Forbidden))
//			}
//
//			return next(c)
//		}
//	}
//}

//// Role based auth middleware, using ctx user
//func (mw *MiddlewareManager) RoleBasedAuthMiddleware(roles []string) echo.MiddlewareFunc {
//	return func(next echo.HandlerFunc) echo.HandlerFunc {
//		return func(c echo.Context) error {
//			user, ok := c.Get("user").(*models.User)
//			if !ok {
//				mw.logger.Errorf("Error c.Get(user) RequestID: %s, UserID: %s, ERROR: %s,",
//					utils.GetRequestID(c),
//					user.UserID.String(),
//					"invalid user ctx",
//				)
//				return c.JSON(http.StatusUnauthorized, httpErrors.NewUnauthorizedError(httpErrors.Unauthorized))
//			}
//
//			for _, role := range roles {
//				if role == *user.Role {
//					return next(c)
//				}
//			}
//
//			mw.logger.Errorf("Error c.Get(user) RequestID: %s, UserID: %s, ERROR: %s,",
//				utils.GetRequestID(c),
//				user.UserID.String(),
//				"invalid user ctx",
//			)
//
//			return c.JSON(http.StatusForbidden, httpErrors.NewForbiddenError(httpErrors.PermissionDenied))
//		}
//	}
//}

func (mw *MiddlewareManager) validateJWTToken(tokenString string, authUC auth.UseCase, c echo.Context, cfg *config.Config) error {
	if tokenString == "" {
		return httpErrors.InvalidJWTToken
	}
	mw.logger.Infof("Validating JWT token, tokenString: %s", tokenString)

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signin method %v", token.Header["alg"])
		}
		secret := []byte(cfg.Server.JwtSecretKey)
		return secret, nil
	})
	mw.logger.Infof("Validating JWT token, token: %#v", token)
	if err != nil {
		return err
	}

	if !token.Valid {
		return httpErrors.InvalidJWTToken
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		mw.logger.Infof("Validating JWT token claims, claims: %#v", claims)
		userID, ok := claims["id"].(string)
		if !ok {
			return httpErrors.InvalidJWTClaims
		}

		userUUID, err := uuid.Parse(userID)
		mw.logger.Infof("Validating JWT token claims, userID: %s, userUUID: %s", userID, userUUID.String())
		if err != nil {
			return err
		}

		u, err := authUC.GetByID(c.Request().Context(), userUUID)
		mw.logger.Infof("Validating JWT token claims, u: %s")
		if err != nil {
			return err
		}

		c.Set("user", u)
		mw.logger.Infof("set user in the context, u.UserID: %s, u.Email: %s", u.UserID, u.Email)

		ctx := context.WithValue(c.Request().Context(), utils.UserCtxKey{}, u)
		mw.logger.Infof("ctx: %#v", ctx)
		c.SetRequest(c.Request().WithContext(ctx))
		mw.logger.Infof("c: %#v", c)
	}
	return nil
}

//// Check auth middleware
//func (mw *MiddlewareManager) CheckAuth(next echo.HandlerFunc) echo.HandlerFunc {
//	return func(ctx echo.Context) error {
//		cookie, err := ctx.Cookie("session_id")
//		if err != nil {
//			mw.logger.Errorf("CheckAuth.ctx.Cookie: %s, Cookie: %#v, Error: %s",
//				utils.GetRequestID(ctx),
//				cookie,
//				err,
//			)
//			return ctx.JSON(http.StatusUnauthorized, httpErrors.NewUnauthorizedError(err))
//		}
//		sid := cookie.Value
//
//		session, err := mw.sessUC.GetSessionByID(ctx.Request().Context(), sid)
//		if err != nil {
//			// Cookie is invalid, delete it from browser
//			newCookie := http.Cookie{Name: "session_id", Value: sid, Expires: time.Now().AddDate(-1, 0, 0)}
//			ctx.SetCookie(&newCookie)
//
//			mw.logger.Errorf("CheckAuth.sessUC.GetSessionByID: %s, Cookie: %#v, Error: %s",
//				utils.GetRequestID(ctx),
//				cookie,
//				err,
//			)
//			return ctx.JSON(http.StatusUnauthorized, httpErrors.NoCookie)
//		}
//
//		ctx.Set("uid", session.SessionID)
//		ctx.Set("sid", sid)
//		return next(ctx)
//	}
//}
