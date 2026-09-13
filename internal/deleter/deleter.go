package deleter

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
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

// Deleter handles safe deletion, deny-list checks, and audit logging.
type Deleter struct {
	HomeDir     string
	AuditLogDir string
	LogFile     string
	mu          sync.Mutex
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
	Errors       []string
	IsDryRun     bool
}

// DeleteBatch processes a list of candidates safely.
func (d *Deleter) DeleteBatch(candidates []DeleteCandidate, dryRun bool) (*DeleteResult, error) {
	res := &DeleteResult{IsDryRun: dryRun}

	if !dryRun {
		if err := os.MkdirAll(d.AuditLogDir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create audit log directory: %w", err)
		}
	}

	for _, c := range candidates {
		// 1. Strict deny-list check
		if d.IsDenied(c.Path) {
			res.SkippedCount++
			res.SkippedSize += c.Size
			res.Errors = append(res.Errors, fmt.Sprintf("DENIED (protected system path): %s", c.Path))
			continue
		}

		// 2. Check if file actually exists
		if _, err := os.Lstat(c.Path); os.IsNotExist(err) {
			continue
		}

		if dryRun {
			res.DeletedCount++
			res.DeletedSize += c.Size
			continue
		}

		// 3. Move to Trash
		if err := d.moveToTrash(c.Path); err != nil {
			res.SkippedCount++
			res.SkippedSize += c.Size
			res.Errors = append(res.Errors, fmt.Sprintf("Failed to trash %s: %v", c.Path, err))
			continue
		}

		res.DeletedCount++
		res.DeletedSize += c.Size

		// 4. Log to audit file
		_ = d.logDeletion(c.Path, c.Size)
	}

	return res, nil
}

// moveToTrash moves a file to macOS ~/.Trash via AppleScript Finder command,
// falling back to direct move into ~/.Trash if Finder command is unavailable.
func (d *Deleter) moveToTrash(targetPath string) error {
	absPath, err := filepath.Abs(targetPath)
	if err != nil {
		absPath = targetPath
	}

	// AppleScript tell Finder to delete POSIX file moves item to Trash with "Put Back" support
	appleScript := fmt.Sprintf(`tell application "Finder" to delete POSIX file %q`, absPath)
	cmd := exec.Command("osascript", "-e", appleScript)
	if err := cmd.Run(); err == nil {
		return nil
	}

	// Fallback: move directly to ~/.Trash
	trashDir := filepath.Join(d.HomeDir, ".Trash")
	if err := os.MkdirAll(trashDir, 0700); err != nil {
		return err
	}

	baseName := filepath.Base(absPath)
	dest := filepath.Join(trashDir, baseName)

	// Avoid overwriting existing items in Trash
	if _, err := os.Lstat(dest); err == nil {
		dest = filepath.Join(trashDir, fmt.Sprintf("%s_%d", baseName, time.Now().UnixNano()))
	}

	return os.Rename(absPath, dest)
}

// logDeletion appends an audit entry to ~/.maccleaner/deletions.log.
func (d *Deleter) logDeletion(path string, size int64) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	f, err := os.OpenFile(d.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	timestamp := time.Now().Format(time.RFC3339)
	line := fmt.Sprintf("[%s] DELETED [%d bytes] %s\n", timestamp, size, path)
	if _, err := w.WriteString(line); err != nil {
		return err
	}
	return w.Flush()
}
