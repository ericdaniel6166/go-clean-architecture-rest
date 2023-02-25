//go:generate mockgen -source pg_repository.go -destination mock/pg_repository_mock.go -package mock
package auth

import (
	"context"
	"github.com/google/uuid"
	"go-clean-architecture-rest/internal/models"
	"go-clean-architecture-rest/pkg/utils"
)

// Repository Auth repository interface
type Repository interface {
	Register(ctx context.Context, user *models.User) (*models.User, error)
	FindByEmail(ctx context.Context, user *models.User) (*models.User, error)
	GetByID(ctx context.Context, userID uuid.UUID) (*models.User, error)
	GetUsers(ctx context.Context, pq *utils.PaginationQuery) (*models.UsersList, error)
	//Update(ctx context.Context, user *models.User) (*models.User, error)
	//Delete(ctx context.Context, userID uuid.UUID) error
	//FindByName(ctx context.Context, name string, query *utils.PaginationQuery) (*models.UsersList, error)

}
