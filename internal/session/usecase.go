//go:generate mockgen -source usecase.go -destination mock/usecase_mock.go -package mock
package session

// UCSession Session use case
type UCSession interface {
	//CreateSession(ctx context.Context, session *models.Session, expire int) (string, error)
	//GetSessionByID(ctx context.Context, sessionID string) (*models.Session, error)
	//DeleteByID(ctx context.Context, sessionID string) error
}
