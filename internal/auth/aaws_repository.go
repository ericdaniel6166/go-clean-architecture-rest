//go:generate mockgen -source aws_repository.go -destination mock/aws_repository_mock.go -package mock
package auth

// AWSRepository Minio AWS S3 interface
type AWSRepository interface {
	//PutObject(ctx context.Context, input models.UploadInput) (*minio.UploadInfo, error)
	//GetObject(ctx context.Context, bucket string, fileName string) (*minio.Object, error)
	//RemoveObject(ctx context.Context, bucket string, fileName string) error
}