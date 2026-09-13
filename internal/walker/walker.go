package walker

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sync"
)

// FileHandler is called for every non-directory file encountered during walking.
// Handlers must be safe for concurrent invocation.
type FileHandler func(path string, d fs.DirEntry, info fs.FileInfo) error

// WalkOptions configures the concurrent directory walker.
type WalkOptions struct {
	// MaxWorkers defines max concurrency. If <= 0, defaults to runtime.NumCPU() * 2.
	MaxWorkers int
	// SkipDir returns true if a directory path should not be traversed.
	SkipDir func(path string) bool
	// OnError is invoked when an error occurs reading a directory or file info.
	OnError func(path string, err error)
	// FollowSymlinks dictates whether symlinked directories are traversed. Default false.
	FollowSymlinks bool
}

// ConcurrentWalker traverses filesystem trees concurrently using a worker pool.
type ConcurrentWalker struct {
	opts WalkOptions
	sem  chan struct{}
}

// New creates a new ConcurrentWalker with given options.
func New(opts WalkOptions) *ConcurrentWalker {
	workers := opts.MaxWorkers
	if workers <= 0 {
		workers = runtime.NumCPU() * 2
	}
	if workers < 1 {
		workers = 1
	}
	opts.MaxWorkers = workers

	return &ConcurrentWalker{
		opts: opts,
		sem:  make(chan struct{}, workers),
	}
}

// Walk traverses the directory rooted at root concurrently.
func (w *ConcurrentWalker) Walk(ctx context.Context, root string, handler FileHandler) error {
	return w.WalkMulti(ctx, []string{root}, handler)
}

// WalkMulti traverses multiple roots concurrently.
func (w *ConcurrentWalker) WalkMulti(ctx context.Context, roots []string, handler FileHandler) error {
	var wg sync.WaitGroup

	for _, root := range roots {
		if root == "" {
			continue
		}
		cleanRoot := filepath.Clean(root)
		info, err := os.Lstat(cleanRoot)
		if err != nil {
			if w.opts.OnError != nil {
				w.opts.OnError(cleanRoot, err)
			}
			continue
		}

		if !info.IsDir() {
			// Single file root
			dirEntry := &fileDirEntry{name: filepath.Base(cleanRoot), info: info}
			if err := handler(cleanRoot, dirEntry, info); err != nil {
				if w.opts.OnError != nil {
					w.opts.OnError(cleanRoot, err)
				}
			}
			continue
		}

		if w.opts.SkipDir != nil && w.opts.SkipDir(cleanRoot) {
			continue
		}

		wg.Add(1)
		w.dispatch(ctx, cleanRoot, handler, &wg)
	}

	wg.Wait()
	return ctx.Err()
}

// dispatch either schedules walking the directory in a new goroutine if capacity permits,
// or executes it inline to prevent unbounded goroutines and deadlock.
func (w *ConcurrentWalker) dispatch(ctx context.Context, dir string, handler FileHandler, wg *sync.WaitGroup) {
	select {
	case <-ctx.Done():
		wg.Done()
		return
	case w.sem <- struct{}{}:
		go func() {
			defer func() {
				<-w.sem
				wg.Done()
			}()
			w.walkDir(ctx, dir, handler, wg)
		}()
	default:
		// Saturated pool: run in current goroutine
		defer wg.Done()
		w.walkDir(ctx, dir, handler, wg)
	}
}

// walkDir reads entries of a directory and handles files/subdirectories.
func (w *ConcurrentWalker) walkDir(ctx context.Context, dir string, handler FileHandler, wg *sync.WaitGroup) {
	select {
	case <-ctx.Done():
		return
	default:
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		if w.opts.OnError != nil && !errors.Is(err, fs.ErrNotExist) {
			w.opts.OnError(dir, err)
		}
		return
	}

	for _, entry := range entries {
		select {
		case <-ctx.Done():
			return
		default:
		}

		path := filepath.Join(dir, entry.Name())

		if entry.IsDir() {
			if w.opts.SkipDir != nil && w.opts.SkipDir(path) {
				continue
			}
			wg.Add(1)
			w.dispatch(ctx, path, handler, wg)
			continue
		}

		isSymlink := entry.Type()&fs.ModeSymlink != 0
		if isSymlink && w.opts.FollowSymlinks {
			targetInfo, err := os.Stat(path)
			if err == nil && targetInfo.IsDir() {
				if w.opts.SkipDir != nil && w.opts.SkipDir(path) {
					continue
				}
				wg.Add(1)
				w.dispatch(ctx, path, handler, wg)
				continue
			}
		}

		info, err := entry.Info()
		if err != nil {
			if w.opts.OnError != nil && !errors.Is(err, fs.ErrNotExist) {
				w.opts.OnError(path, err)
			}
			continue
		}

		if err := handler(path, entry, info); err != nil {
			if w.opts.OnError != nil {
				w.opts.OnError(path, err)
			}
		}
	}
}

// fileDirEntry adapts os.FileInfo to fs.DirEntry for single-file roots.
type fileDirEntry struct {
	name string
	info fs.FileInfo
}

func (e *fileDirEntry) Name() string               { return e.name }
func (e *fileDirEntry) IsDir() bool                { return e.info.IsDir() }
func (e *fileDirEntry) Type() fs.FileMode          { return e.info.Mode().Type() }
func (e *fileDirEntry) Info() (fs.FileInfo, error) { return e.info, nil }
