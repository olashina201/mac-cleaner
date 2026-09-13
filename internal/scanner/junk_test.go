package scanner

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestJunkScanner(t *testing.T) {
	tempBase, err := os.MkdirTemp("", "maccleaner_junk_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempBase)

	cacheDir := filepath.Join(tempBase, "Caches")
	downloadsDir := filepath.Join(tempBase, "Downloads")
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(downloadsDir, 0755); err != nil {
		t.Fatal(err)
	}

	// 1. Old cache file: 40 days old
	oldFile := filepath.Join(cacheDir, "old_cache.data")
	if err := os.WriteFile(oldFile, []byte("old cache data here"), 0644); err != nil {
		t.Fatal(err)
	}
	oldTime := time.Now().Add(-40 * 24 * time.Hour)
	if err := os.Chtimes(oldFile, oldTime, oldTime); err != nil {
		t.Fatal(err)
	}

	// 2. Fresh cache file: 5 days old
	freshFile := filepath.Join(cacheDir, "fresh_cache.data")
	if err := os.WriteFile(freshFile, []byte("fresh cache"), 0644); err != nil {
		t.Fatal(err)
	}
	freshTime := time.Now().Add(-5 * 24 * time.Hour)
	if err := os.Chtimes(freshFile, freshTime, freshTime); err != nil {
		t.Fatal(err)
	}

	// 3. Old download file: 50 days old (but in ListOnly category!)
	downloadFile := filepath.Join(downloadsDir, "installer.dmg")
	if err := os.WriteFile(downloadFile, []byte("large installer binary"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(downloadFile, oldTime, oldTime); err != nil {
		t.Fatal(err)
	}

	rules := []JunkTargetRule{
		{
			Name:     "Test Caches",
			Pattern:  cacheDir,
			ListOnly: false,
		},
		{
			Name:     "Test Downloads",
			Pattern:  downloadsDir,
			ListOnly: true,
		},
	}

	scanner := NewJunkScanner(rules, 30)
	result, err := scanner.Scan(context.Background())
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	// In Test Caches: 2 files total, 1 candidate (the old one)
	var cacheStats *CategoryStats
	var dlStats *CategoryStats
	for _, c := range result.Categories {
		if c.Name == "Test Caches" {
			cacheStats = c
		} else if c.Name == "Test Downloads" {
			dlStats = c
		}
	}

	if cacheStats == nil || dlStats == nil {
		t.Fatal("Expected categories not found in result")
	}

	if cacheStats.TotalFiles != 2 {
		t.Errorf("Expected 2 total files in Caches, got %d", cacheStats.TotalFiles)
	}
	if cacheStats.CandidateCount != 1 {
		t.Errorf("Expected 1 candidate file in Caches, got %d", cacheStats.CandidateCount)
	}
	if cacheStats.CandidateSize != int64(len("old cache data here")) {
		t.Errorf("Expected candidate size %d, got %d", len("old cache data here"), cacheStats.CandidateSize)
	}

	// In Test Downloads: ListOnly is true, so CandidateCount must be 0
	if dlStats.CandidateCount != 0 {
		t.Errorf("Downloads is ListOnly, candidate count must be 0, got %d", dlStats.CandidateCount)
	}
	if dlStats.TotalFiles != 1 {
		t.Errorf("Expected 1 total file in Downloads, got %d", dlStats.TotalFiles)
	}

	if result.CandidateCount != 1 {
		t.Errorf("Expected overall candidate count 1, got %d", result.CandidateCount)
	}
}
