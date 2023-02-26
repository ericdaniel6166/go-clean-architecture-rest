package usecase

import (
	"context"
	"database/sql"
	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/opentracing/opentracing-go"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
	"go-clean-architecture-rest/config"
	"go-clean-architecture-rest/internal/auth/mock"
	"go-clean-architecture-rest/internal/models"
	"go-clean-architecture-rest/pkg/httpErrors"
	"go-clean-architecture-rest/pkg/logger"
	"go-clean-architecture-rest/pkg/utils"
	"net/http"
	"testing"
)

func TestAuthUC_Register(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	cfg := &config.Config{
		Server: config.ServerConfig{
			JwtSecretKey: "secret",
		},
		Logger: config.Logger{
			Development:       true,
			DisableCaller:     false,
			DisableStacktrace: false,
			Encoding:          "json",
		},
	}

	apiLogger := logger.NewApiLogger(cfg)
	mockAuthRepo := mock.NewMockRepository(ctrl)
	authUC := NewAuthUseCase(cfg, mockAuthRepo, nil, nil, apiLogger)

	user := &models.User{
		Password: "123456",
		Email:    "email@gmail.com",
	}

	ctx := context.Background()
	span, ctxWithTrace := opentracing.StartSpanFromContext(ctx, "authUC.UploadAvatar")
	defer span.Finish()

	mockAuthRepo.EXPECT().FindByEmail(ctxWithTrace, gomock.Eq(user)).Return(nil, sql.ErrNoRows)
	mockAuthRepo.EXPECT().Register(ctxWithTrace, gomock.Eq(user)).Return(user, nil)

	createdUSer, err := authUC.Register(ctx, user)
	require.NoError(t, err)
	require.NotNil(t, createdUSer)
	require.Nil(t, err)
}

func TestAuthUC_Register2(t *testing.T) {
	t.Parallel()

	cfg, apiLogger := utils.Setup()

	uid := uuid.New()
	user := utils.RandomUser()
	token := utils.RandomString(10)

	errRegister := errors.New("ErrRegister")

	testCases := []struct {
		name          string
		buildStub     func(mockAuthRepo *mock.MockRepository, ctxWithTrace context.Context, user *models.User)
		user          models.User
		createdUser   func(user models.User, uid uuid.UUID, token string) *models.UserWithToken
		checkResponse func(expected *models.UserWithToken, actual *models.UserWithToken, err error)
	}{
		{
			name: "OK",
			buildStub: func(mockAuthRepo *mock.MockRepository, ctxWithTrace context.Context, user *models.User) {
				mockAuthRepo.EXPECT().FindByEmail(ctxWithTrace, gomock.Eq(user)).Return(nil, sql.ErrNoRows)
				mockAuthRepo.EXPECT().Register(ctxWithTrace, gomock.Eq(user)).Return(user, nil)
			},
			user: user,
			createdUser: func(user models.User, uid uuid.UUID, token string) *models.UserWithToken {
				return utils.BuildUserWithToken(user, uid, token)
			},
			checkResponse: func(expected *models.UserWithToken, actual *models.UserWithToken, err error) {
				require.NotNil(t, actual)
				require.NoError(t, err)
				require.Equal(t, expected.User.Email, actual.User.Email)
			},
		},
		{
			name: "ErrRegister",
			buildStub: func(mockAuthRepo *mock.MockRepository, ctxWithTrace context.Context, user *models.User) {
				mockAuthRepo.EXPECT().FindByEmail(ctxWithTrace, gomock.Eq(user)).Return(nil, sql.ErrNoRows)

				mockAuthRepo.EXPECT().Register(ctxWithTrace, gomock.Eq(user)).Return(nil, errRegister)
			},
			user: user,
			createdUser: func(user models.User, uid uuid.UUID, token string) *models.UserWithToken {
				return nil
			},
			checkResponse: func(expected *models.UserWithToken, actual *models.UserWithToken, err error) {
				require.Nil(t, actual)
				require.Error(t, err)
				require.EqualError(t, err, errRegister.Error())
			},
		},
		{
			name: "StatusBadRequest_ErrEmailAlreadyExists",
			buildStub: func(mockAuthRepo *mock.MockRepository, ctxWithTrace context.Context, user *models.User) {
				mockAuthRepo.EXPECT().FindByEmail(ctxWithTrace, gomock.Eq(user)).Return(user, nil)
			},
			user: user,
			createdUser: func(user models.User, uid uuid.UUID, token string) *models.UserWithToken {
				return nil
			},
			checkResponse: func(expected *models.UserWithToken, actual *models.UserWithToken, err error) {
				require.Error(t, err)
				require.Nil(t, actual)
				require.EqualError(t, err.(httpErrors.RestErr), httpErrors.NewRestErrorWithMessage(http.StatusBadRequest, httpErrors.ErrEmailAlreadyExists, nil).Error())
			},
		},
	}

	for i := range testCases {
		tc := testCases[i]
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockAuthRepo := mock.NewMockRepository(ctrl)
			authUC := NewAuthUseCase(cfg, mockAuthRepo, nil, nil, apiLogger)

			ctx := context.Background()
			span, ctxWithTrace := opentracing.StartSpanFromContext(ctx, "authUC.UploadAvatar")
			defer span.Finish()

			user := tc.user
			tc.buildStub(mockAuthRepo, ctxWithTrace, &user)

			actual, err := authUC.Register(ctx, &user)

			tc.checkResponse(tc.createdUser(user, uid, token), actual, err)

		})
	}

}
