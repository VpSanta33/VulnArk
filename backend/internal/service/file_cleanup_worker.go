package service

import (
	"context"
	"errors"
	"io/fs"
	"time"

	"vulnark/internal/repository"
)

type FileDeleter interface {
	DeleteFile(string) error
}

type FileCleanupWorkerOptions struct {
	BatchSize    int
	PollInterval time.Duration
	Lease        time.Duration
	RetryBase    time.Duration
	RetryMax     time.Duration
	OnError      func(error)
}

type FileCleanupWorker struct {
	repo    repository.FileCleanupRepository
	storage FileDeleter
	opts    FileCleanupWorkerOptions
}

func NewFileCleanupWorker(repo repository.FileCleanupRepository, storage FileDeleter, opts FileCleanupWorkerOptions) *FileCleanupWorker {
	if opts.BatchSize <= 0 || opts.BatchSize > 100 {
		opts.BatchSize = 20
	}
	if opts.PollInterval <= 0 {
		opts.PollInterval = 5 * time.Second
	}
	if opts.Lease <= 0 || opts.Lease > 10*time.Minute {
		opts.Lease = time.Minute
	}
	if opts.RetryBase <= 0 {
		opts.RetryBase = 5 * time.Second
	}
	if opts.RetryMax <= 0 {
		opts.RetryMax = time.Hour
	}
	return &FileCleanupWorker{repo: repo, storage: storage, opts: opts}
}

func (w *FileCleanupWorker) retryDelay(attempt uint) time.Duration {
	delay := w.opts.RetryBase
	for i := uint(1); i < attempt && delay < w.opts.RetryMax; i++ {
		if delay > w.opts.RetryMax/2 {
			return w.opts.RetryMax
		}
		delay *= 2
	}
	if delay > w.opts.RetryMax {
		return w.opts.RetryMax
	}
	return delay
}

// RunBatch performs at most BatchSize deletions. The task remains durable until
// the filesystem deletion and fenced completion both succeed.
func (w *FileCleanupWorker) RunBatch(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	tasks, claimErr := w.repo.Claim(ctx, w.opts.BatchSize, w.opts.Lease)
	errs := []error{claimErr}
	for _, task := range tasks {
		if err := ctx.Err(); err != nil {
			return errors.Join(append(errs, err)...)
		}
		err := w.storage.DeleteFile(task.FilePath)
		if err == nil || errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, w.repo.Complete(ctx, task))
			continue
		}
		// Persist a delayed retry, retaining an inspectable bounded error. If this
		// update fails, the original claim expires and another worker recovers it.
		errs = append(errs, err, w.repo.Retry(ctx, task, w.retryDelay(task.Attempts), err))
	}
	return errors.Join(errs...)
}

// Run starts with a recovery sweep and exits promptly at cancellation between
// storage calls. Storage implementations must keep DeleteFile bounded.
func (w *FileCleanupWorker) Run(ctx context.Context) error {
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			if err := w.RunBatch(ctx); err != nil && ctx.Err() == nil && w.opts.OnError != nil {
				w.opts.OnError(err)
			}
			timer.Reset(w.opts.PollInterval)
		}
	}
}
