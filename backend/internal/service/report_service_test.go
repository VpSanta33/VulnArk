package service

import (
	"errors"
	"fmt"
	"mime/multipart"
	"testing"

	"github.com/stretchr/testify/require"
	"vulnark/internal/model"
	"vulnark/internal/repository"
	"vulnark/pkg/storage"
)

type reportUploadFailureStorage struct {
	storage.StorageService
	err error
}

func (s reportUploadFailureStorage) UploadFile(*multipart.FileHeader, string) (*storage.FileInfo, error) {
	return nil, s.err
}

type reportCleanupCaptureRepository struct {
	repository.ReportRepository
	paths []string
	err   error
}

func (r *reportCleanupCaptureRepository) QueueFileCleanup(paths []string) error {
	r.paths = append(r.paths, paths...)
	return r.err
}

type reportUploadUserRepository struct{ repository.UserRepository }

func (reportUploadUserRepository) GetByID(id uint) (*model.User, error) {
	return &model.User{ID: id}, nil
}

func TestReportUploadPartialWriteFailureQueuesCleanup(t *testing.T) {
	writeErr := errors.New("partial write removal failed")
	queueErr := errors.New("queue unavailable")
	for _, test := range []struct {
		name      string
		uploadErr error
		queueErr  error
		wantPath  bool
	}{
		{"plain upload failure", writeErr, nil, false},
		{"partial file", &storage.CleanupError{FilePath: "reports/partial.pdf", Err: writeErr}, nil, true},
		{"wrapped partial file", fmt.Errorf("upload: %w", &storage.CleanupError{FilePath: "reports/partial.pdf", Err: writeErr}), nil, true},
		{"enqueue failure propagated", &storage.CleanupError{FilePath: "reports/partial.pdf", Err: writeErr}, queueErr, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			repo := &reportCleanupCaptureRepository{err: test.queueErr}
			svc := NewReportService(repo, nil, nil, reportUploadUserRepository{}, nil, reportUploadFailureStorage{err: test.uploadErr})
			report, err := svc.UploadReport(&model.ReportUploadRequest{Title: "test"}, &multipart.FileHeader{Filename: "report.pdf", Size: 100}, 7)
			require.Nil(t, report)
			require.ErrorIs(t, err, writeErr)
			if test.wantPath {
				require.Equal(t, []string{"reports/partial.pdf"}, repo.paths)
			} else {
				require.Empty(t, repo.paths)
			}
			if test.queueErr != nil {
				require.ErrorIs(t, err, queueErr)
				require.ErrorContains(t, err, "持久化文件补偿失败")
			}
		})
	}
}
