package scanner

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"maccleaner/internal/walker"
)

// JunkTargetRule defines a location pattern and policy for junk scanning.
type JunkTargetRule struct {
	Name        string
	Pattern     string
	ListOnly    bool   // If true, items are listed for review only and never marked as safe-to-delete
	Description string
}

// DefaultJunkRules returns the standard macOS junk scanning locations.
func DefaultJunkRules() []JunkTargetRule {
	return []JunkTargetRule{
		{
			Name:        "User Caches",
			Pattern:     "~/Library/Caches",
			ListOnly:    false,
			Description: "Application caches stored in user library",
		},
		{
			Name:        "User Logs",
			Pattern:     "~/Library/Logs",
			ListOnly:    false,
			Description: "Crash reports and application log files",
		},
		{
			Name:        "App Support Caches",
			Pattern:     "~/Library/Application Support/*/Cache",
			ListOnly:    false,
			Description: "Third-party application cache directories",
		},
		{
			Name:        "System Logs",
			Pattern:     "/private/var/log",
			ListOnly:    false,
			Description: "System level log files",
		},
		{
			Name:        "Temporary Files",
			Pattern:     "/private/var/folders/*/*/T",
			ListOnly:    false,
			Description: "Per-user system temporary directories",
		},
		{
			Name:        "Xcode DerivedData",
			Pattern:     "~/Library/Developer/Xcode/DerivedData",
			ListOnly:    false,
			Description: "Xcode build artifacts and index data",
		},
		{
			Name:        "Xcode Archives",
			Pattern:     "~/Library/Developer/Xcode/Archives",
			ListOnly:    false,
			Description: "Packaged Xcode app archives",
		},
		{
			Name:        "App Container Caches",
			Pattern:     "~/Library/Containers/*/Data/Library/Caches",
			ListOnly:    false,
			Description: "Sandboxed app container caches",
		},
		{
			Name:        "Downloads",
			Pattern:     "~/Downloads",
			ListOnly:    true, // List only, never auto-delete!
			Description: "Downloaded files (listed for review only, never auto-deleted)",
		},
	}
}

// JunkItem represents a file found during junk scanning.
type JunkItem struct {
	Path     string
	Size     int64
	ModTime  time.Time
	Category string
	ListOnly bool
}

// CategoryStats aggregates scanning statistics for a target rule.
type CategoryStats struct {
	Name           string
	Pattern        string
	MatchedPaths   []string
	TotalFiles     int64
	TotalSize      int64
	CandidateCount int64
	CandidateSize  int64
	ListOnly       bool
}

// JunkScanResult contains the aggregated results from a junk scan.
type JunkScanResult struct {
	ThresholdDays  int
	Categories     []*CategoryStats
	Candidates     []JunkItem
	TotalFiles     int64
	TotalSize      int64
	CandidateCount int64
	CandidateSize  int64
	ScanDuration   time.Duration
}

// JunkScanner scans predefined junk directories.
type JunkScanner struct {
	Rules         []JunkTargetRule
	ThresholdDays int
	HomeDir       string
	Walker        *walker.ConcurrentWalker
}

// NewJunkScanner creates a new scanner with rules and threshold.
func NewJunkScanner(rules []JunkTargetRule, thresholdDays int) *JunkScanner {
	if rules == nil {
		rules = DefaultJunkRules()
	}
	home, err := os.UserHomeDir()
	if err != nil {
		home = os.Getenv("HOME")
	}

	return &JunkScanner{
		Rules:         rules,
		ThresholdDays: thresholdDays,
		HomeDir:       home,
		Walker:        walker.New(walker.WalkOptions{}),
	}
}

// ExpandPath expands tildes and glob patterns to concrete absolute directory paths.
func (s *JunkScanner) ExpandPath(pattern string) []string {
	if strings.HasPrefix(pattern, "~/") || pattern == "~" {
		pattern = filepath.Join(s.HomeDir, strings.TrimPrefix(pattern, "~"))
	}

	if strings.ContainsAny(pattern, "*?[") {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			return nil
		}
		var valid []string
		for _, m := range matches {
			if fi, err := os.Stat(m); err == nil && fi.IsDir() {
				valid = append(valid, m)
			}
		}
		return valid
	}

	// Direct path
	if fi, err := os.Stat(pattern); err == nil && fi.IsDir() {
		return []string{pattern}
	}

	return nil
}

// Scan executes the junk scan across all configured target rules.
func (s *JunkScanner) Scan(ctx context.Context) (*JunkScanResult, error) {
	startTime := time.Now()
	now := time.Now()
	thresholdDuration := time.Duration(s.ThresholdDays) * 24 * time.Hour

	result := &JunkScanResult{
		ThresholdDays: s.ThresholdDays,
		Categories:    make([]*CategoryStats, 0, len(s.Rules)),
	}

	var allCandidates []JunkItem
	var candMu sync.Mutex

	for _, rule := range s.Rules {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		matchedPaths := s.ExpandPath(rule.Pattern)
		stats := &CategoryStats{
			Name:         rule.Name,
			Pattern:      rule.Pattern,
			MatchedPaths: matchedPaths,
			ListOnly:     rule.ListOnly,
		}
		result.Categories = append(result.Categories, stats)

		if len(matchedPaths) == 0 {
			continue
		}

		var (
			catTotalFiles     int64
			catTotalSize      int64
			catCandidateCount int64
			catCandidateSize  int64
		)

		err := s.Walker.WalkMulti(ctx, matchedPaths, func(path string, d fs.DirEntry, info fs.FileInfo) error {
			size := info.Size()
			atomic.AddInt64(&catTotalFiles, 1)
			atomic.AddInt64(&catTotalSize, size)

			// Check age threshold
			age := now.Sub(info.ModTime())
			if age >= thresholdDuration && !rule.ListOnly {
				atomic.AddInt64(&catCandidateCount, 1)
				atomic.AddInt64(&catCandidateSize, size)

				candMu.Lock()
				allCandidates = append(allCandidates, JunkItem{
					Path:     path,
					Size:     size,
					ModTime:  info.ModTime(),
					Category: rule.Name,
					ListOnly: false,
				})
				candMu.Unlock()
			} else if rule.ListOnly {
				candMu.Lock()
				allCandidates = append(allCandidates, JunkItem{
					Path:     path,
					Size:     size,
					ModTime:  info.ModTime(),
					Category: rule.Name,
					ListOnly: true,
				})
				candMu.Unlock()
			}

			return nil
		})

		if err != nil && ctx.Err() != nil {
			return nil, ctx.Err()
		}

		stats.TotalFiles = catTotalFiles
		stats.TotalSize = catTotalSize
		stats.CandidateCount = catCandidateCount
		stats.CandidateSize = catCandidateSize

		result.TotalFiles += catTotalFiles
		result.TotalSize += catTotalSize
		result.CandidateCount += catCandidateCount
		result.CandidateSize += catCandidateSize
	}

	result.Candidates = allCandidates
	result.ScanDuration = time.Since(startTime)

	return result, nil
}
