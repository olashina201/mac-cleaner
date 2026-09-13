package scanner

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// DevArtifact represents a project-level dependency or build directory.
type DevArtifact struct {
	Path         string
	ProjectDir   string
	ProjectName  string
	ArtifactType string
	Size         int64
	FileCount    int64
	LastActivity time.Time
	DaysInactive int
	SafeToDelete bool
}

// DevScanResult aggregates findings from scanning developer directories.
type DevScanResult struct {
	ThresholdDays  int
	SearchRoots    []string
	Artifacts      []DevArtifact
	TotalSize      int64
	TotalFiles     int64
	CandidateCount int64
	CandidateSize  int64
	ScanDuration   time.Duration
}

// DevScanner searches for project build artifacts and dependencies.
type DevScanner struct {
	SearchRoots   []string
	ThresholdDays int
	HomeDir       string
}

// NewDevScanner creates a new developer artifact scanner.
func NewDevScanner(roots []string, thresholdDays int) *DevScanner {
	home, err := os.UserHomeDir()
	if err != nil {
		home = os.Getenv("HOME")
	}

	if len(roots) == 0 {
		roots = detectDefaultDevRoots(home)
	}

	return &DevScanner{
		SearchRoots:   roots,
		ThresholdDays: thresholdDays,
		HomeDir:       home,
	}
}

// detectDefaultDevRoots finds common project directories on the user's system.
func detectDefaultDevRoots(home string) []string {
	candidates := []string{
		filepath.Join(home, "Documents", "projects"),
		filepath.Join(home, "Documents", "Projects"),
		filepath.Join(home, "Projects"),
		filepath.Join(home, "Developer"),
		filepath.Join(home, "Development"),
		filepath.Join(home, "workspace"),
		filepath.Join(home, "code"),
		filepath.Join(home, "src"),
		filepath.Join(home, "git"),
	}

	var existing []string
	for _, c := range candidates {
		if fi, err := os.Stat(c); err == nil && fi.IsDir() {
			existing = append(existing, c)
		}
	}

	// Fallback to home if no standard dev directories exist
	if len(existing) == 0 {
		existing = []string{home}
	}

	return existing
}

// Scan traverses configured roots and identifies dormant project artifacts.
func (s *DevScanner) Scan(ctx context.Context) (*DevScanResult, error) {
	startTime := time.Now()
	now := time.Now()
	thresholdDuration := time.Duration(s.ThresholdDays) * 24 * time.Hour

	result := &DevScanResult{
		ThresholdDays: s.ThresholdDays,
		SearchRoots:   s.SearchRoots,
	}

	var artifacts []DevArtifact
	var mu sync.Mutex

	for _, root := range s.SearchRoots {
		cleanRoot := filepath.Clean(root)
		if fi, err := os.Stat(cleanRoot); err != nil || !fi.IsDir() {
			continue
		}

		_ = s.walkDevDir(ctx, cleanRoot, 0, 5, func(art DevArtifact) {
			mu.Lock()
			artifacts = append(artifacts, art)
			mu.Unlock()
		})
	}

	for i := range artifacts {
		art := &artifacts[i]
		days := int(now.Sub(art.LastActivity).Hours() / 24)
		if days < 0 {
			days = 0
		}
		art.DaysInactive = days
		if now.Sub(art.LastActivity) >= thresholdDuration {
			art.SafeToDelete = true
			result.CandidateCount++
			result.CandidateSize += art.Size
		}

		result.TotalSize += art.Size
		result.TotalFiles += art.FileCount
	}

	result.Artifacts = artifacts
	result.ScanDuration = time.Since(startTime)
	return result, nil
}

// walkDevDir recursively searches for artifact directories without descending into them.
func (s *DevScanner) walkDevDir(ctx context.Context, dir string, depth int, maxDepth int, onFound func(DevArtifact)) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	if depth > maxDepth {
		return nil
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}

	for _, entry := range entries {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if !entry.IsDir() {
			continue
		}

		name := entry.Name()
		fullPath := filepath.Join(dir, name)

		// Skip system and hidden directories
		if s.shouldSkipDir(name, fullPath) {
			continue
		}

		// Check if this directory is a known artifact
		artifactType := s.classifyArtifact(name, dir)
		if artifactType != "" {
			// Found a project artifact (e.g. node_modules, target, .venv)
			size, count := calculateDirSize(ctx, fullPath)
			lastActive := s.detectProjectActivity(dir)

			onFound(DevArtifact{
				Path:         fullPath,
				ProjectDir:   dir,
				ProjectName:  filepath.Base(dir),
				ArtifactType: artifactType,
				Size:         size,
				FileCount:    count,
				LastActivity: lastActive,
			})

			// Prune traversal: DO NOT recurse inside artifact directory!
			continue
		}

		// Recurse into subdirectories
		_ = s.walkDevDir(ctx, fullPath, depth+1, maxDepth, onFound)
	}

	return nil
}

// classifyArtifact checks if a directory name corresponds to a valid project artifact.
func (s *DevScanner) classifyArtifact(dirName string, parentDir string) string {
	switch dirName {
	case "node_modules":
		// Must be inside a JavaScript/TypeScript project
		if fileExists(filepath.Join(parentDir, "package.json")) {
			return "node_modules"
		}
	case ".next":
		if fileExists(filepath.Join(parentDir, "package.json")) ||
			fileExists(filepath.Join(parentDir, "next.config.js")) ||
			fileExists(filepath.Join(parentDir, "next.config.ts")) ||
			fileExists(filepath.Join(parentDir, "next.config.mjs")) {
			return ".next"
		}
	case "target":
		// Must be inside a Rust Cargo project
		if fileExists(filepath.Join(parentDir, "Cargo.toml")) {
			return "target (Cargo)"
		}
	case ".venv", "venv":
		// Python virtual environment
		if fileExists(filepath.Join(parentDir, dirName, "bin", "activate")) ||
			fileExists(filepath.Join(parentDir, dirName, "pyvenv.cfg")) {
			return "venv (Python)"
		}
	case ".turbo":
		if fileExists(filepath.Join(parentDir, "turbo.json")) || fileExists(filepath.Join(parentDir, "package.json")) {
			return ".turbo"
		}
	case "Pods":
		if fileExists(filepath.Join(parentDir, "Podfile")) {
			return "Pods (CocoaPods)"
		}
	}
	return ""
}

// shouldSkipDir filters out system, library, and non-project folders.
func (s *DevScanner) shouldSkipDir(name string, fullPath string) bool {
	if strings.HasPrefix(name, ".") && name != ".next" && name != ".venv" && name != ".turbo" {
		return true // Skip .git, .cache, etc.
	}
	if name == "Library" || name == "Applications" || name == ".Trash" {
		return true
	}
	// Skip node_modules inside node_modules if encountered
	if name == "node_modules" || name == "vendor" {
		return false // Handled in classifyArtifact
	}
	return false
}

// detectProjectActivity determines the most recent modification time in a project.
func (s *DevScanner) detectProjectActivity(projectDir string) time.Time {
	latest := time.Time{}

	// Key files to check
	checkPaths := []string{
		filepath.Join(projectDir, ".git", "FETCH_HEAD"),
		filepath.Join(projectDir, ".git", "index"),
		filepath.Join(projectDir, ".git", "HEAD"),
		filepath.Join(projectDir, "package.json"),
		filepath.Join(projectDir, "Cargo.toml"),
		filepath.Join(projectDir, "pyproject.toml"),
		filepath.Join(projectDir, "src"),
		filepath.Join(projectDir, "app"),
		projectDir,
	}

	for _, p := range checkPaths {
		if fi, err := os.Stat(p); err == nil {
			if fi.ModTime().After(latest) {
				latest = fi.ModTime()
			}
		}
	}

	if latest.IsZero() {
		if fi, err := os.Stat(projectDir); err == nil {
			return fi.ModTime()
		}
		return time.Now().Add(-365 * 24 * time.Hour) // Default to old if unknown
	}

	return latest
}

// calculateDirSize computes total size and file count inside an artifact directory.
func calculateDirSize(ctx context.Context, dirPath string) (int64, int64) {
	var totalSize int64
	var totalCount int64

	_ = filepath.WalkDir(dirPath, func(path string, d fs.DirEntry, err error) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if err != nil {
			return nil
		}
		if !d.IsDir() {
			if info, err := d.Info(); err == nil {
				totalSize += info.Size()
				totalCount++
			}
		}
		return nil
	})

	return totalSize, totalCount
}

func fileExists(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && !fi.IsDir()
}
