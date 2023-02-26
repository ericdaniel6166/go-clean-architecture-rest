package utils

import (
	"github.com/google/uuid"
	"go-clean-architecture-rest/config"
	"go-clean-architecture-rest/internal/models"
	"go-clean-architecture-rest/pkg/logger"
)

func Setup() (*config.Config, logger.Logger) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			JwtSecretKey: "secret",
		},
		Session: config.Session{
			Expire: 10,
		},
		Logger: config.Logger{
			Development:       true,
			DisableCaller:     false,
			DisableStacktrace: false,
			Encoding:          "json",
		},
	}

	apiLogger := logger.NewApiLogger(cfg)
	apiLogger.InitLogger()

	return cfg, apiLogger
}

func BuildUserWithToken(user models.User, uid uuid.UUID, token string) *models.UserWithToken {
	createdUser := user
	createdUser.UserID = uid
	u := &models.UserWithToken{
		User:  &createdUser,
		Token: token,
	}
	return u
}
