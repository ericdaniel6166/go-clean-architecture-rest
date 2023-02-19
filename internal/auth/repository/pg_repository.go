package repository

import (
	"context"
	"github.com/jmoiron/sqlx"
	"github.com/pkg/errors"
	"go-clean-architecture-rest/internal/auth"
	"go-clean-architecture-rest/internal/models"
)

// Auth Repository
type authRepo struct {
	db *sqlx.DB
}

// NewAuthRepository Auth Repository constructor
func NewAuthRepository(db *sqlx.DB) auth.Repository {
	return &authRepo{db: db}
}

// Register Create new user
func (r *authRepo) Register(ctx context.Context, user *models.User) (*models.User, error) {
	//span, ctx := opentracing.StartSpanFromContext(ctx, "authRepo.Register")
	//defer span.Finish()

	u := &models.User{}
	if err := r.db.QueryRowxContext(ctx, createUserQuery, &user.FirstName, &user.LastName, &user.Email,
		&user.Password, &user.Role, &user.About, &user.Avatar, &user.PhoneNumber, &user.Address, &user.City,
		&user.Gender, &user.Postcode, &user.Birthday,
	).StructScan(u); err != nil {
		return nil, errors.Wrap(err, "authRepo.Register.StructScan")
	}

	return u, nil
}

// FindByEmail Find user by email
func (r *authRepo) FindByEmail(ctx context.Context, user *models.User) (*models.User, error) {
	//span, ctx := opentracing.StartSpanFromContext(ctx, "authRepo.FindByEmail")
	//defer span.Finish()

	foundUser := &models.User{}
	if err := r.db.QueryRowxContext(ctx, findUserByEmail, user.Email).StructScan(foundUser); err != nil {
		return nil, errors.Wrap(err, "authRepo.FindByEmail.QueryRowxContext")
	}
	return foundUser, nil
}
