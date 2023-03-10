package http

import (
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/opentracing/opentracing-go"
	"go-clean-architecture-rest/config"
	"go-clean-architecture-rest/internal/auth"
	"go-clean-architecture-rest/internal/models"
	"go-clean-architecture-rest/internal/session"
	"go-clean-architecture-rest/pkg/csrf"
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

// GetCSRFToken godoc
// @Summary Get CSRF token
// @Description Get CSRF token, required auth session cookie
// @Tags Auth
// @Accept json
// @Produce json
// @Success 200 {string} string "Ok"
// @Failure 500 {object} httpErrors.RestError
// @Router /auth/token [get]
func (h *authHandlers) GetCSRFToken() echo.HandlerFunc {
	return func(c echo.Context) error {
		span, _ := opentracing.StartSpanFromContext(utils.GetRequestCtx(c), "authHandlers.GetCSRFToken")
		defer span.Finish()

		//sid, ok := c.Get("sid").(string)
		user, ok := c.Get("user").(*models.User)
		if !ok {
			return utils.ErrResponseWithLog(c, h.logger, httpErrors.NewUnauthorizedError(httpErrors.Unauthorized))
		}
		//h.logger.Infof("GetCSRFToken, RequestID: %s, sid: %s", utils.GetRequestID(c), sid)
		//token := csrf.MakeToken(sid, h.logger)
		uid := user.UserID
		h.logger.Infof("GetCSRFToken, RequestID: %s, uid: %s", utils.GetRequestID(c), uid)
		token := csrf.MakeToken(uid.String(), h.logger)
		h.logger.Infof("GetCSRFToken, RequestID: %s, token: %s", utils.GetRequestID(c), token)
		c.Response().Header().Set(csrf.CSRFHeader, token)
		c.Response().Header().Set("Access-Control-Expose-Headers", csrf.CSRFHeader)

		return c.NoContent(http.StatusOK)
	}
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
			utils.LogResponseError(c, h.logger, err)
			return c.JSON(httpErrors.ErrorResponse(err))
		}

		createdUser, err := h.authUC.Register(ctx, user)
		if err != nil {
			utils.LogResponseError(c, h.logger, err)
			return c.JSON(httpErrors.ErrorResponse(err))
		}

		//err = h.handleSession(c, ctx, createdUser.User.UserID)
		//if err != nil {
		//	utils.LogResponseError(c, h.logger, err)
		//	return c.JSON(httpErrors.ErrorResponse(err))
		//}

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

		//err = h.handleSession(c, ctx, userWithToken.User.UserID)
		//if err != nil {
		//	utils.LogResponseError(c, h.logger, err)
		//	return c.JSON(httpErrors.ErrorResponse(err))
		//}

		return c.JSON(http.StatusOK, userWithToken)
	}
}

//func (h *authHandlers) handleSession(c echo.Context, ctx context.Context, userID uuid.UUID) error {
//	sess, err := h.sessUC.CreateSession(ctx, &models.Session{
//		UserID: userID,
//	}, h.cfg.Session.Expire)
//	if err != nil {
//		return err
//	}
//	h.logger.Infof("session created, RequestID: %s, sess: %s", utils.GetRequestID(c), sess)
//
//	sessionCookie := utils.CreateSessionCookie(h.cfg, sess)
//	c.SetCookie(sessionCookie)
//	h.logger.Infof("set sessionCookie in the context, RequestID: %s, sessionCookie: %s", utils.GetRequestID(c), sessionCookie)
//	return nil
//}

// GetMe godoc
// @Summary Get current user
// @Description Get current user
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
			return utils.ErrResponseWithLog(c, h.logger, httpErrors.NewUnauthorizedError(httpErrors.Unauthorized))
		}
		return c.JSON(http.StatusOK, user)
	}
}

// GetUserByID godoc
// @Summary get user by id
// @Description get user by ID
// @Tags Auth
// @Accept  json
// @Produce  json
// @Param path variable "user_id"
// @Success 200 {object} models.User
// @Failure 500 {object} httpErrors.RestError
// @Router /auth/{user_id} [get]
func (h *authHandlers) GetUserByID() echo.HandlerFunc {
	return func(c echo.Context) error {
		span, ctx := opentracing.StartSpanFromContext(utils.GetRequestCtx(c), "authHandlers.GetUserByID")
		defer span.Finish()

		uid, err := uuid.Parse(c.Param("user_id"))
		if err != nil {
			utils.LogResponseError(c, h.logger, err)
			return c.JSON(httpErrors.ErrorResponse(err))
		}

		user, err := h.authUC.GetByID(ctx, uid)
		if err != nil {
			utils.LogResponseError(c, h.logger, err)
			return c.JSON(httpErrors.ErrorResponse(err))
		}

		return c.JSON(http.StatusOK, user)
	}
}

// GetUsers godoc
// @Summary Get users
// @Description Get the list of all users
// @Tags Auth
// @Accept json
// @Param page query int false "page number" Format(page)
// @Param size query int false "number of elements per page" Format(size)
// @Param orderBy query int false "filter name" Format(orderBy)
// @Produce json
// @Success 200 {object} models.UsersList
// @Failure 500 {object} httpErrors.RestError
// @Router /auth/all [get]
func (h *authHandlers) GetUsers() echo.HandlerFunc {
	return func(c echo.Context) error {
		span, ctx := opentracing.StartSpanFromContext(utils.GetRequestCtx(c), "authHandlers.GetUsers")
		defer span.Finish()

		paginationQuery, err := utils.GetPaginationFromCtx(c)
		if err != nil {
			utils.LogResponseError(c, h.logger, err)
			return c.JSON(httpErrors.ErrorResponse(err))
		}

		usersList, err := h.authUC.GetUsers(ctx, paginationQuery)
		if err != nil {
			utils.LogResponseError(c, h.logger, err)
			return c.JSON(httpErrors.ErrorResponse(err))
		}

		return c.JSON(http.StatusOK, usersList)
	}
}
