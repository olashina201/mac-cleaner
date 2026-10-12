package deleter

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

// DeniedPrefixes contains critical macOS system paths that must NEVER be deleted.
var DeniedPrefixes = []string{
	"/System",
	"/usr",
	"/bin",
	"/sbin",
	"/private/var/db",
	"/Library/Apple",
	"/Library/SystemExtensions",
	"/private/etc",
	"/etc",
	"/Applications",
	"/Library", // Root /Library is protected; ~/Library is user library
}

// maxReportedErrors caps how many per-file error lines are kept in the
// result. The counts are always exact; only the verbose list is truncated so
// huge batches don't blow up memory or flood the UI.
const maxReportedErrors = 20

// Deleter handles safe deletion, deny-list checks, and audit logging.
type Deleter struct {
	HomeDir     string
	AuditLogDir string
	LogFile     string
	// Workers caps deletion concurrency. <=0 means auto (NumCPU*2, min 8).
	Workers int
	mu      sync.Mutex
}

// New creates a new Deleter instance.
func New() (*Deleter, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		home = os.Getenv("HOME")
	}
	if home == "" {
		return nil, fmt.Errorf("could not determine user home directory")
	}

	auditDir := filepath.Join(home, ".maccleaner")
	logFile := filepath.Join(auditDir, "deletions.log")

	return &Deleter{
		HomeDir:     home,
		AuditLogDir: auditDir,
		LogFile:     logFile,
	}, nil
}

// IsDenied checks if a path falls under protected system directories or root paths.
func (d *Deleter) IsDenied(path string) bool {
	clean := filepath.Clean(path)

	// Block filesystem root or empty paths
	if clean == "/" || clean == "." || clean == "" {
		return true
	}

	// Block user home root
	if clean == d.HomeDir {
		return true
	}

	// Check against hardcoded denied system paths
	for _, prefix := range DeniedPrefixes {
		if clean == prefix || strings.HasPrefix(clean, prefix+"/") {
			return true
		}
	}

	return false
}

// DeleteCandidate represents an item to be safely removed.
type DeleteCandidate struct {
	Path     string
	Size     int64
	Category string
}

// DeleteResult summarizes the outcome of a deletion batch.
type DeleteResult struct {
	DeletedCount int64
	DeletedSize  int64
	SkippedCount int64
	SkippedSize  int64
	// PermissionDeniedCount tracks files skipped because they are not
	// writable without elevation (subset of SkippedCount). Reported
	// separately so the UI can suggest a single remediation instead of
	// one auth prompt per file.
	PermissionDeniedCount int64
	PermissionDeniedSize  int64
	Errors                []string
	// TruncatedErrors is true when Errors was capped at maxReportedErrors.
	TruncatedErrors bool
	IsDryRun        bool
}

// ProgressFunc is called as deletions complete. done counts finished items
// (deleted + skipped), total is the number of candidates.
type ProgressFunc func(done, total int64)

// DeleteBatch processes a list of candidates safely.
func (d *Deleter) DeleteBatch(candidates []DeleteCandidate, dryRun bool) (*DeleteResult, error) {
	return d.DeleteBatchWithProgress(candidates, dryRun, nil)
}

// DeleteBatchWithProgress is DeleteBatch with an optional progress callback.
// The callback may be invoked concurrently; implementations must be goroutine-safe.
func (d *Deleter) DeleteBatchWithProgress(candidates []DeleteCandidate, dryRun bool, onProgress ProgressFunc) (*DeleteResult, error) {
	res := &DeleteResult{IsDryRun: dryRun}

	if !dryRun {
		if err := os.MkdirAll(d.AuditLogDir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create audit log directory: %w", err)
		}
	}

	type work struct {
		cand DeleteCandidate
	}

	// Pre-flight: deny-list, existence, and writability. Anything that would
	// previously have triggered a per-file Finder auth prompt (and then
	// failed anyway) is skipped here with zero prompts.
	var queue []work
	for _, c := range candidates {
		if d.IsDenied(c.Path) {
			res.SkippedCount++
			res.SkippedSize += c.Size
			appendError(res, fmt.Sprintf("DENIED (protected system path): %s", c.Path))
			continue
		}
		if _, err := os.Lstat(c.Path); os.IsNotExist(err) {
			continue
		} else if err != nil {
			res.SkippedCount++
			res.SkippedSize += c.Size
			appendError(res, fmt.Sprintf("Failed to stat %s: %v", c.Path, err))
			continue
		}
		if dryRun {
			res.DeletedCount++
			res.DeletedSize += c.Size
			continue
		}
		if reason, ok := d.writabilityBlockReason(c.Path); !ok {
			res.SkippedCount++
			res.SkippedSize += c.Size
			res.PermissionDeniedCount++
			res.PermissionDeniedSize += c.Size
			appendError(res, fmt.Sprintf("SKIPPED (needs elevation — %s): %s", reason, c.Path))
			continue
		}
		queue = append(queue, work{cand: c})
	}

	total := int64(len(candidates))
	var done atomic.Int64
	reportProgress := func() {
		if onProgress != nil {
			onProgress(done.Add(1), total)
		} else {
			done.Add(1)
		}
	}
	// Account for items already resolved in pre-flight.
	done.Store(int64(len(candidates) - len(queue)))
	if onProgress != nil && len(queue) == 0 {
		onProgress(done.Load(), total)
	}
	if len(queue) == 0 {
		finalizePermissionHint(res)
		return res, nil
	}

	// Ensure Trash exists once instead of per file.
	trashDir := filepath.Join(d.HomeDir, ".Trash")
	if err := os.MkdirAll(trashDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to prepare Trash directory: %w", err)
	}

	workers := d.Workers
	if workers <= 0 {
		workers = runtime.NumCPU() * 2
		if workers < 8 {
			workers = 8
		}
		if workers > 32 {
			workers = 32
		}
	}
	if workers > len(queue) {
		workers = len(queue)
	}

	jobs := make(chan work)
	var wg sync.WaitGroup
	var resMu sync.Mutex
	var successes []deletedEntry

	worker := func() {
		defer wg.Done()
		for j := range jobs {
			// Fast path: direct rename into ~/.Trash. This never
			// triggers a macOS auth dialog — unlike per-file Finder
			// AppleScript — so permission failures surface as plain
			// errors we can batch and summarize.
			if err := moveToTrashFast(trashDir, j.cand.Path); err != nil {
				resMu.Lock()
				res.SkippedCount++
				res.SkippedSize += j.cand.Size
				if isPermissionError(err) {
					res.PermissionDeniedCount++
					res.PermissionDeniedSize += j.cand.Size
					appendErrorLocked(res, fmt.Sprintf("SKIPPED (needs elevation): %s", j.cand.Path))
				} else {
					appendErrorLocked(res, fmt.Sprintf("Failed to trash %s: %v", j.cand.Path, err))
				}
				resMu.Unlock()
			} else {
				resMu.Lock()
				res.DeletedCount++
				res.DeletedSize += j.cand.Size
				successes = append(successes, deletedEntry{path: j.cand.Path, size: j.cand.Size})
				resMu.Unlock()
			}
			reportProgress()
		}
	}

	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go worker()
	}
	for _, j := range queue {
		jobs <- j
	}
	close(jobs)
	wg.Wait()

	// Single batched audit-log write instead of one open/write/close per file.
	if len(successes) > 0 {
		if err := d.logDeletions(successes); err != nil {
			appendError(res, fmt.Sprintf("Warning: audit log write failed: %v", err))
		}
	}

	finalizePermissionHint(res)
	return res, nil
}

// writabilityBlockReason reports whether moving path into Trash is doomed
// without elevation. Moving a file requires write+execute on its parent
// directory, so that is what is checked — no deletion is attempted, hence no
// auth prompt. ok=false means the file should be skipped upfront.
func (d *Deleter) writabilityBlockReason(path string) (reason string, ok bool) {
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}
	parent := filepath.Dir(abs)

	// W_OK|X_OK on the parent dir is the real requirement for rename.
	if err := unix.Access(parent, unix.W_OK|unix.X_OK); err != nil {
		if errors.Is(err, unix.EACCES) || errors.Is(err, unix.EPERM) || errors.Is(err, unix.EROFS) {
			return "parent directory is not writable", false
		}
		return "parent directory is not accessible", false
	}
	// Note: a read-only filesystem will fail the rename below; that failure
	// is classified as a permission error and skipped without prompting,
	// so no separate statfs check is needed here (it is not portable
	// across darwin/linux statfs structs).
	return "", true
}

// isPermissionError classifies post-attempt failures that mean "re-run
// elevated or exclude this path" rather than a transient I/O problem.
func isPermissionError(err error) bool {
	if err == nil {
		return false
	}
	if os.IsPermission(err) || errors.Is(err, unix.EACCES) || errors.Is(err, unix.EPERM) || errors.Is(err, unix.EROFS) {
		return true
	}
	msg := strings.ToLower(err.Error())
	for _, s := range []string{
		"permission denied", "operation not permitted", "not permitted",
		"read-only file system", "read only file system", "sip", "system integrity protection",
	} {
		if strings.Contains(msg, s) {
			return true
		}
	}
	return false
}

// appendError records a per-file message, capping the retained list while
// keeping the counts exact.
func appendError(res *DeleteResult, msg string) {
	if len(res.Errors) < maxReportedErrors {
		res.Errors = append(res.Errors, msg)
	} else {
		res.TruncatedErrors = true
	}
}

func appendErrorLocked(res *DeleteResult, msg string) {
	if len(res.Errors) < maxReportedErrors {
		res.Errors = append(res.Errors, msg)
	} else {
		res.TruncatedErrors = true
	}
}

// finalizePermissionHint appends a single actionable summary when files were
// skipped for elevation, replacing what used to be one auth prompt per file.
func finalizePermissionHint(res *DeleteResult) {
	if res.PermissionDeniedCount == 0 || res.IsDryRun {
		return
	}
	hidden := res.SkippedCount - int64(len(res.Errors))
	_ = hidden
	res.Errors = append(res.Errors, fmt.Sprintf(
		"Hint: %d item(s) need elevated permissions and were skipped without prompting. "+
			"Re-run with sudo to include them, or leave them to keep system files untouched.",
		res.PermissionDeniedCount,
	))
}

// moveToTrashFast renames targetPath directly into trashDir with a unique
// destination name. It performs no authorization prompts; failures are
// returned for batch classification.
func moveToTrashFast(trashDir, targetPath string) error {
	absPath, err := filepath.Abs(targetPath)
	if err != nil {
		absPath = targetPath
	}
	baseName := filepath.Base(absPath)
	dest := filepath.Join(trashDir, baseName)
	if _, err := os.Lstat(dest); err == nil {
		dest = filepath.Join(trashDir, fmt.Sprintf("%s_%d", baseName, time.Now().UnixNano()))
	}
	if err := os.Rename(absPath, dest); err != nil {
		return err
	}
	return nil
}

// deletedEntry is one successful trash move pending an audit-log write.
type deletedEntry struct {
	path string
	size int64
}

// logDeletions appends audit entries for a batch of deletions in one write.
func (d *Deleter) logDeletions(items []deletedEntry) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	f, err := os.OpenFile(d.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	for _, it := range items {
		timestamp := time.Now().Format(time.RFC3339)
		line := fmt.Sprintf("[%s] DELETED [%d bytes] %s\n", timestamp, it.size, it.path)
		if _, err := w.WriteString(line); err != nil {
			return err
		}
	}
	return w.Flush()
}

// logDeletion appends a single audit entry. Kept for compatibility; the batch
// path uses logDeletions for a single batched write.
func (d *Deleter) logDeletion(path string, size int64) error {
	return d.logDeletions([]deletedEntry{{path: path, size: size}})
}
