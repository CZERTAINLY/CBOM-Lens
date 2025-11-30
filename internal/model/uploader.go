package model

import "context"

type Uploader interface {
	Upload(ctx context.Context, jobName string, raw []byte) error
}

type UploadCloser interface {
	Uploader
	Close() error
}
