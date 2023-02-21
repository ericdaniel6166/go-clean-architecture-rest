package http

import (
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/opentracing/opentracing-go"
	"go-clean-architecture-rest/config"
	"go-clean-architecture-rest/internal/auth"
	"go-clean-architecture-rest/internal/models"
	"go-clean-architecture-rest/internal/session"
	"go-clean-architecture-rest/pkg/httpErrors"
	"go-clean-architecture-rest/pkg/logger"
	"go-clean-architecture-rest/pkg/utils"
	"net/http"
)

// Auth handlers
type authHandlers struct {
	cfg    *config.Config
	authUC auth.UseCase
	sessUC session.UCSession
	logger logger.Logger
}

// NewAuthHandlers Auth handlers constructor
func NewAuthHandlers(cfg *config.Config, authUC auth.UseCase, sessUC session.UCSession, log logger.Logger) auth.Handlers {
	return &authHandlers{cfg: cfg, authUC: authUC, sessUC: sessUC, logger: log}
}

// Register godoc
// @Summary Register new user
// @Description register new user, returns user and token
// @Tags Auth
// @Accept json
// @Produce json
// @Success 201 {object} models.User
// @Router /auth/register [post]
func (h *authHandlers) Register() echo.HandlerFunc {

	return func(c echo.Context) error {
		span, ctx := opentracing.StartSpanFromContext(utils.GetRequestCtx(c), "auth.Register")
		defer span.Finish()

		user := &models.User{}
		if err := utils.ReadRequest(c, user); err != nil {
			h.logger.Errorf("Failed to read request: %v", err)
			utils.LogResponseError(c, h.logger, err)
			return c.JSON(httpErrors.ErrorResponse(err))
		}

		createdUser, err := h.authUC.Register(ctx, user)
		if err != nil {
			h.logger.Errorf("Failed to register user: %v", err)
			utils.LogResponseError(c, h.logger, err)

			return c.JSON(httpErrors.ErrorResponse(err))
		}

		sess, err := h.sessUC.CreateSession(ctx, &models.Session{
			UserID: createdUser.User.UserID,
		}, h.cfg.Session.Expire)
		if err != nil {
			utils.LogResponseError(c, h.logger, err)
			return c.JSON(httpErrors.ErrorResponse(err))
		}
		h.logger.Infof("session created: %#v", sess)

		sessionCookie := utils.CreateSessionCookie(h.cfg, sess)
		c.SetCookie(sessionCookie)
		h.logger.Infof("set sessionCookie in the context, sessionCookie: %s", sessionCookie)

		return c.JSON(http.StatusCreated, createdUser)
	}
}

// Login godoc
// @Summary Login new user
// @Description login user, returns user and set session
// @Tags Auth
// @Accept json
// @Produce json
// @Success 200 {object} models.User
// @Router /auth/login [post]
func (h *authHandlers) Login() echo.HandlerFunc {
	type Login struct {
		Email    string `json:"email" db:"email" validate:"omitempty,lte=60,email"`
		Password string `json:"password,omitempty" db:"password" validate:"required,gte=6"`
	}
	return func(c echo.Context) error {
		span, ctx := opentracing.StartSpanFromContext(utils.GetRequestCtx(c), "auth.Login")
		defer span.Finish()

		login := &Login{}
		if err := utils.ReadRequest(c, login); err != nil {
			utils.LogResponseError(c, h.logger, err)
			return c.JSON(httpErrors.ErrorResponse(err))
		}

		userWithToken, err := h.authUC.Login(ctx, &models.User{
			Email:    login.Email,
			Password: login.Password,
		})
		if err != nil {
			utils.LogResponseError(c, h.logger, err)
			return c.JSON(httpErrors.ErrorResponse(err))
		}

		sess, err := h.sessUC.CreateSession(ctx, &models.Session{
			UserID: userWithToken.User.UserID,
		}, h.cfg.Session.Expire)
		if err != nil {
			utils.LogResponseError(c, h.logger, err)
			return c.JSON(httpErrors.ErrorResponse(err))
		}
		h.logger.Infof("session created: %s", sess)

		sessionCookie := utils.CreateSessionCookie(h.cfg, sess)
		c.SetCookie(sessionCookie)
		h.logger.Infof("set sessionCookie in the context, sessionCookie: %s", sessionCookie)

		return c.JSON(http.StatusOK, userWithToken)
	}
}

// GetMe godoc
// @Summary Get user by id
// @Description Get current user by id
// @Tags Auth
// @Accept json
// @Produce json
// @Success 200 {object} models.User
// @Failure 500 {object} httpErrors.RestError
// @Router /auth/me [get]
func (h *authHandlers) GetMe() echo.HandlerFunc {
	return func(c echo.Context) error {
		span, _ := opentracing.StartSpanFromContext(utils.GetRequestCtx(c), "authHandlers.GetMe")
		defer span.Finish()

		user, ok := c.Get("user").(*models.User)
		if !ok {
			utils.LogResponseError(c, h.logger, httpErrors.NewUnauthorizedError(httpErrors.Unauthorized))
			return utils.ErrResponseWithLog(c, h.logger, httpErrors.NewUnauthorizedError(httpErrors.Unauthorized))
		}
		h.logger.Infof("get user from context, user.UserID: %d, user.Email: %s", user.UserID.String(), user.Email)

		return c.JSON(http.StatusOK, user)
	}
}

// GetUserByID godoc
// @Summary get user by id
// @Description get string by ID
// @Tags Auth
// @Accept  json
// @Produce  json
// @Param id path int true "user_id"
// @Success 200 {object} models.User
// @Failure 500 {object} httpErrors.RestError
// @Router /auth/{id} [get]
func (h *authHandlers) GetUserByID() echo.HandlerFunc {
	return func(c echo.Context) error {
		span, ctx := opentracing.StartSpanFromContext(utils.GetRequestCtx(c), "authHandlers.GetUserByID")
		defer span.Finish()

		uID, err := uuid.Parse(c.Param("user_id"))
		if err != nil {
			utils.LogResponseError(c, h.logger, err)
			return c.JSON(httpErrors.ErrorResponse(err))
		}
		h.logger.Infof("parse user_id from context, user_id: %s, uID: %s", c.Param("user_id"), uID)

		user, err := h.authUC.GetByID(ctx, uID)
		if err != nil {
			utils.LogResponseError(c, h.logger, err)
			return c.JSON(httpErrors.ErrorResponse(err))
		}
		h.logger.Infof("get user by id, uID: %s, user.UserID: %s, user.Email: %s", uID, user.UserID, user.Email)

		return c.JSON(http.StatusOK, user)
	}
}
