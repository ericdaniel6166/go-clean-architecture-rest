//go:generate mockgen -source pg_repository.go -destination mock/pg_repository_mock.go -package mock
package auth

import (
	"context"
	"go-clean-architecture-rest/internal/models"
)

// Repository Auth repository interface
type Repository interface {
	Register(ctx context.Context, user *models.User) (*models.User, error)
	FindByEmail(ctx context.Context, user *models.User) (*models.User, error)
	//Update(ctx context.Context, user *models.User) (*models.User, error)
	//Delete(ctx context.Context, userID uuid.UUID) error
	//GetByID(ctx context.Context, userID uuid.UUID) (*models.User, error)
	//FindByName(ctx context.Context, name string, query *utils.PaginationQuery) (*models.UsersList, error)

	//GetUsers(ctx context.Context, pq *utils.PaginationQuery) (*models.UsersList, error)
}
