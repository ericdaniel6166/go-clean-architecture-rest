package http

import (
	"github.com/labstack/echo/v4"
	"github.com/labstack/gommon/log"
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
		//span, ctx := opentracing.StartSpanFromContext(utils.GetRequestCtx(c), "auth.Register")
		//defer span.Finish()

		user := &models.User{}
		if err := utils.ReadRequest(c, user); err != nil {
			//utils.LogResponseError(c, h.logger, err)
			log.Errorf("error read request: %s", err)

			return c.JSON(httpErrors.ErrorResponse(err))
		}

		//createdUser, err := h.authUC.Register(ctx, user)
		createdUser, err := h.authUC.Register(utils.GetRequestCtx(c), user)
		if err != nil {
			//utils.LogResponseError(c, h.logger, err)
			log.Errorf("error register new user: %s", err)

			return c.JSON(httpErrors.ErrorResponse(err))
		}

		//sess, err := h.sessUC.CreateSession(ctx, &models.Session{
		//	UserID: createdUser.User.UserID,
		//}, h.cfg.Session.Expire)
		//if err != nil {
		//	utils.LogResponseError(c, h.logger, err)
		//	return c.JSON(httpErrors.ErrorResponse(err))
		//}

		//c.SetCookie(utils.CreateSessionCookie(h.cfg, sess))

		return c.JSON(http.StatusCreated, createdUser)
	}
}
