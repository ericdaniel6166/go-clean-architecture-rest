package repository

import (
	"context"
	"database/sql/driver"
	"github.com/DATA-DOG/go-sqlmock"
	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/require"
	"go-clean-architecture-rest/internal/models"
	"go-clean-architecture-rest/pkg/utils"
	"testing"
)

func TestAuthRepo_Register(t *testing.T) {
	t.Parallel()

	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
	require.NoError(t, err)
	defer db.Close()

	sqlxDB := sqlx.NewDb(db, "sqlmock")
	defer sqlxDB.Close()

	authRepo := NewAuthRepository(sqlxDB)

	t.Run("Register", func(t *testing.T) {
		gender := "male"
		role := "admin"

		rows := sqlmock.NewRows([]string{"first_name", "last_name", "password", "email", "role", "gender"}).AddRow(
			"Alex", "Bryksin", "123456", "alex@gmail.com", "admin", &gender)

		user := &models.User{
			FirstName: "Alex",
			LastName:  "Bryksin",
			Email:     "alex@gmail.com",
			Password:  "123456",
			Role:      &role,
			Gender:    &gender,
		}

		mock.ExpectQuery(createUserQuery).WithArgs(&user.FirstName, &user.LastName, &user.Email,
			&user.Password, &user.Role, &user.About, &user.Avatar, &user.PhoneNumber, &user.Address, &user.City,
			&user.Gender, &user.Postcode, &user.Birthday).WillReturnRows(rows)

		createdUser, err := authRepo.Register(context.Background(), user)

		require.NoError(t, err)
		require.NotNil(t, createdUser)
		require.Equal(t, createdUser, user)
	})
}

func TestAuthRepo_Register2(t *testing.T) {
	t.Parallel()

	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
	require.NoError(t, err)
	defer db.Close()

	sqlxDB := sqlx.NewDb(db, "sqlmock")
	defer sqlxDB.Close()

	authRepo := NewAuthRepository(sqlxDB)

	user := utils.RandomUser()

	testCases := []struct {
		name          string
		buildStubs    func(user *models.User, rows *sqlmock.Rows)
		user          *models.User
		rows          *sqlmock.Rows
		checkResponse func(expected *models.User, actual *models.User, err error)
	}{
		{
			name: "OK",
			buildStubs: func(user *models.User, rows *sqlmock.Rows) {
				mock.ExpectQuery(createUserQuery).WithArgs(user.FirstName, user.LastName, user.Email,
					user.Password, user.Role, user.About, user.Avatar, user.PhoneNumber, user.Address, user.City,
					user.Gender, user.Postcode, user.Birthday).WillReturnRows(rows)

			},
			user: &user,
			rows: sqlmock.NewRows([]string{"first_name", "last_name", "password", "email", "role", "gender"}).AddRow(
				user.FirstName, user.LastName, user.Password, user.Email, user.Role, user.Gender),
			checkResponse: func(expected *models.User, actual *models.User, err error) {
				require.NoError(t, err)
				require.NotNil(t, actual)
				require.Equal(t, expected, actual)
			},
		},
		{
			name: "ErrBadConn",
			buildStubs: func(user *models.User, rows *sqlmock.Rows) {
				mock.ExpectQuery(createUserQuery).WithArgs(user.FirstName, user.LastName, user.Email,
					user.Password, user.Role, user.About, user.Avatar, user.PhoneNumber, user.Address, user.City,
					user.Gender, user.Postcode, user.Birthday).WillReturnError(driver.ErrBadConn)

			},
			user: &user,
			rows: nil,
			checkResponse: func(expected *models.User, actual *models.User, err error) {
				require.Error(t, err)
				require.Nil(t, actual)
			},
		},
	}

	for i := range testCases {
		tc := testCases[i]
		t.Run(tc.name, func(t *testing.T) {
			tc.buildStubs(tc.user, tc.rows)
			actual, err := authRepo.Register(context.Background(), tc.user)
			tc.checkResponse(tc.user, actual, err)
		})

	}

}
