//go:generate mockgen -source usecase.go -destination mock/usecase_mock.go -package mock
package auth

import (
	"context"
	"github.com/google/uuid"
	"go-clean-architecture-rest/internal/models"
	"go-clean-architecture-rest/pkg/utils"
)

// UseCase Auth repository interface
type UseCase interface {
	Register(ctx context.Context, user *models.User) (*models.UserWithToken, error)
	Login(ctx context.Context, user *models.User) (*models.UserWithToken, error)
	GetByID(ctx context.Context, userID uuid.UUID) (*models.User, error)
	GetUsers(ctx context.Context, pq *utils.PaginationQuery) (*models.UsersList, error)
	//Update(ctx context.Context, user *models.User) (*models.User, error)
	//Delete(ctx context.Context, userID uuid.UUID) error
	//FindByName(ctx context.Context, name string, query *utils.PaginationQuery) (*models.UsersList, error)
	//UploadAvatar(ctx context.Context, userID uuid.UUID, file models.UploadInput) (*models.User, error)
}
