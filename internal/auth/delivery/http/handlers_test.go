package http

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/opentracing/opentracing-go"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
	"go-clean-architecture-rest/config"
	"go-clean-architecture-rest/internal/auth/mock"
	"go-clean-architecture-rest/internal/models"
	mockSess "go-clean-architecture-rest/internal/session/mock"
	"go-clean-architecture-rest/pkg/converter"
	"go-clean-architecture-rest/pkg/httpErrors"
	"go-clean-architecture-rest/pkg/logger"
	"go-clean-architecture-rest/pkg/utils"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAuthHandlers_Register(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAuthUC := mock.NewMockUseCase(ctrl)
	mockSessUC := mockSess.NewMockUCSession(ctrl)

	cfg := &config.Config{
		Session: config.Session{
			Expire: 10,
		},
		Logger: config.Logger{
			Development: true,
		},
	}

	apiLogger := logger.NewApiLogger(cfg)
	apiLogger.InitLogger()
	authHandlers := NewAuthHandlers(cfg, mockAuthUC, mockSessUC, apiLogger)

	gender := "male"
	user := &models.User{
		FirstName: "FirstName",
		LastName:  "LastName",
		Email:     "email@gmail.com",
		Password:  "123456",
		Gender:    &gender,
	}

	buf, err := converter.AnyToBytesBuffer(user)
	require.NoError(t, err)
	require.NotNil(t, buf)
	require.Nil(t, err)

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", strings.NewReader(buf.String()))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()

	c := e.NewContext(req, rec)
	ctx := utils.GetRequestCtx(c)
	span, ctxWithTrace := opentracing.StartSpanFromContext(ctx, "auth.Register")
	defer span.Finish()

	handlerFunc := authHandlers.Register()

	userUID := uuid.New()
	userWithToken := &models.UserWithToken{
		User: &models.User{
			UserID: userUID,
		},
	}
	sess := &models.Session{
		UserID: userUID,
	}
	session := "session"

	mockAuthUC.EXPECT().Register(ctxWithTrace, gomock.Eq(user)).Return(userWithToken, nil)
	mockSessUC.EXPECT().CreateSession(ctxWithTrace, gomock.Eq(sess), 10).Return(session, nil)

	err = handlerFunc(c)
	require.NoError(t, err)
	require.Nil(t, err)
}

func TestAuthHandlers_Register2(t *testing.T) {
	t.Parallel()

	cfg, apiLogger := utils.Setup()

	e := echo.New()

	uid := uuid.New()
	user := utils.RandomUser()
	token := utils.RandomString(10)
	userWithWrongFormatEmail := user
	userWithWrongFormatEmail.Email = "wrong.format.email"

	testCases := []struct {
		name          string
		buildStubs    func(mockAuthUC *mock.MockUseCase, mockSessUC *mockSess.MockUCSession, ctxWithTrace context.Context, user *models.User, createdUser *models.UserWithToken, sess *models.Session)
		user          models.User
		createdUser   func(user models.User, uid uuid.UUID, token string) *models.UserWithToken
		sess          func(uid uuid.UUID) *models.Session
		checkResponse func(recorder *httptest.ResponseRecorder, createdUser *models.UserWithToken)
	}{
		{
			"StatusCreated",
			func(mockAuthUC *mock.MockUseCase, mockSessUC *mockSess.MockUCSession, ctxWithTrace context.Context, user *models.User, createdUser *models.UserWithToken, sess *models.Session) {
				mockAuthUC.EXPECT().Register(ctxWithTrace, gomock.Eq(user)).Return(createdUser, nil)
				mockSessUC.EXPECT().CreateSession(ctxWithTrace, gomock.Eq(sess), 10).Return(utils.RandomString(10), nil)
			},
			user,
			func(user models.User, uid uuid.UUID, token string) *models.UserWithToken {
				return utils.BuildUserWithToken(user, uid, token)
			},
			func(uid uuid.UUID) *models.Session {
				return &models.Session{
					UserID: uid,
				}
			},
			func(recorder *httptest.ResponseRecorder, createdUser *models.UserWithToken) {
				require.Equal(t, http.StatusCreated, recorder.Code)
				requireBodyMatchUser(t, recorder.Body, *createdUser)
			},
		},
		{
			"StatusInternalServerError_ErrCreateSession",
			func(mockAuthUC *mock.MockUseCase, mockSessUC *mockSess.MockUCSession, ctxWithTrace context.Context, user *models.User, createdUser *models.UserWithToken, sess *models.Session) {
				mockAuthUC.EXPECT().Register(ctxWithTrace, gomock.Eq(user)).Return(createdUser, nil)
				mockSessUC.EXPECT().CreateSession(ctxWithTrace, gomock.Eq(sess), 10).Return("", errors.New("ErrCreateSession"))
			},
			user,
			func(user models.User, uid uuid.UUID, token string) *models.UserWithToken {
				return utils.BuildUserWithToken(user, uid, token)
			},
			func(uid uuid.UUID) *models.Session {
				return &models.Session{
					UserID: uid,
				}
			},
			func(recorder *httptest.ResponseRecorder, createdUser *models.UserWithToken) {
				require.Equal(t, http.StatusInternalServerError, recorder.Code)
			},
		},
		{
			"StatusBadRequest_ErrEmailAlreadyExists",
			func(mockAuthUC *mock.MockUseCase, mockSessUC *mockSess.MockUCSession, ctxWithTrace context.Context, user *models.User, createdUser *models.UserWithToken, sess *models.Session) {
				mockAuthUC.EXPECT().Register(ctxWithTrace, gomock.Eq(user)).Return(nil, httpErrors.NewRestErrorWithMessage(http.StatusBadRequest, httpErrors.ErrEmailAlreadyExists, nil))
			},
			user,
			func(user models.User, uid uuid.UUID, token string) *models.UserWithToken {
				return nil
			},
			func(uid uuid.UUID) *models.Session {
				return nil
			},
			func(recorder *httptest.ResponseRecorder, createdUser *models.UserWithToken) {
				require.Equal(t, http.StatusBadRequest, recorder.Code)
			},
		},
		{
			"StatusBadRequest_ErrFieldValidation_InvalidEmail",
			func(mockAuthUC *mock.MockUseCase, mockSessUC *mockSess.MockUCSession, ctxWithTrace context.Context, user *models.User, createdUser *models.UserWithToken, sess *models.Session) {
			},
			userWithWrongFormatEmail,
			func(user models.User, uid uuid.UUID, token string) *models.UserWithToken {
				return nil
			},
			func(uid uuid.UUID) *models.Session {
				return nil
			},
			func(recorder *httptest.ResponseRecorder, createdUser *models.UserWithToken) {
				require.Equal(t, http.StatusBadRequest, recorder.Code)
			},
		},
	}

	for i := range testCases {
		tc := testCases[i]

		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockAuthUC := mock.NewMockUseCase(ctrl)
			mockSessUC := mockSess.NewMockUCSession(ctrl)
			authHandlers := NewAuthHandlers(cfg, mockAuthUC, mockSessUC, apiLogger)

			user := tc.user
			buf, err := converter.AnyToBytesBuffer(user)
			require.NoError(t, err)
			require.NotNil(t, buf)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", strings.NewReader(buf.String()))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()

			c := e.NewContext(req, rec)
			ctx := utils.GetRequestCtx(c)
			span, ctxWithTrace := opentracing.StartSpanFromContext(ctx, "auth.Register")
			defer span.Finish()
			createdUser := tc.createdUser(user, uid, token)
			tc.buildStubs(mockAuthUC, mockSessUC, ctxWithTrace, &user, createdUser, tc.sess(uid))

			handlerFunc := authHandlers.Register()
			err = handlerFunc(c)
			require.NoError(t, err)

			tc.checkResponse(rec, createdUser)
		})
	}
}

//func setup() (*config.Config, logger.Logger, *echo.Echo) {
//	cfg := &config.Config{
//		Session: config.Session{
//			Expire: 10,
//		},
//		Logger: config.Logger{
//			Development: true,
//		},
//	}
//
//	apiLogger := logger.NewApiLogger(cfg)
//	apiLogger.InitLogger()
//
//	e := echo.New()
//	return cfg, apiLogger, e
//}

//func buildUserWithToken(user models.User, uid uuid.UUID, token string) *models.UserWithToken {
//	createdUser := user
//	createdUser.UserID = uid
//	u := &models.UserWithToken{
//		User:  &createdUser,
//		Token: token,
//	}
//	return u
//}

func requireBodyMatchUser(t *testing.T, body *bytes.Buffer, expected models.UserWithToken) {
	data, err := io.ReadAll(body)
	require.NoError(t, err)

	var actual models.UserWithToken
	err = json.Unmarshal(data, &actual)
	require.NoError(t, err)
	require.Equal(t, expected, actual)
}
