package scanner

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDevScanner(t *testing.T) {
	tempDev, err := os.MkdirTemp("", "maccleaner_dev_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDev)

	// 1. Inactive project (60 days old)
	oldProject := filepath.Join(tempDev, "old-app")
	oldNodeModules := filepath.Join(oldProject, "node_modules", "some-dep")
	if err := os.MkdirAll(oldNodeModules, 0755); err != nil {
		t.Fatal(err)
	}
	pkgJsonOld := filepath.Join(oldProject, "package.json")
	if err := os.WriteFile(pkgJsonOld, []byte(`{"name":"old-app"}`), 0644); err != nil {
		t.Fatal(err)
	}
	depFileOld := filepath.Join(oldNodeModules, "index.js")
	if err := os.WriteFile(depFileOld, []byte("console.log('dep')"), 0644); err != nil {
		t.Fatal(err)
	}

	oldDate := time.Now().Add(-60 * 24 * time.Hour)
	_ = os.Chtimes(pkgJsonOld, oldDate, oldDate)
	_ = os.Chtimes(oldProject, oldDate, oldDate)

	// 2. Active project (3 days old)
	activeProject := filepath.Join(tempDev, "active-app")
	activeNodeModules := filepath.Join(activeProject, "node_modules", "some-dep")
	if err := os.MkdirAll(activeNodeModules, 0755); err != nil {
		t.Fatal(err)
	}
	pkgJsonActive := filepath.Join(activeProject, "package.json")
	if err := os.WriteFile(pkgJsonActive, []byte(`{"name":"active-app"}`), 0644); err != nil {
		t.Fatal(err)
	}
	depFileActive := filepath.Join(activeNodeModules, "index.js")
	if err := os.WriteFile(depFileActive, []byte("console.log('dep')"), 0644); err != nil {
		t.Fatal(err)
	}

	recentDate := time.Now().Add(-3 * 24 * time.Hour)
	_ = os.Chtimes(pkgJsonActive, recentDate, recentDate)
	_ = os.Chtimes(activeProject, recentDate, recentDate)

	scanner := NewDevScanner([]string{tempDev}, 30)
	res, err := scanner.Scan(context.Background())
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if len(res.Artifacts) != 2 {
		t.Fatalf("Expected 2 artifacts found, got %d", len(res.Artifacts))
	}

	if res.CandidateCount != 1 {
		t.Errorf("Expected 1 candidate (the old one), got %d", res.CandidateCount)
	}

	var foundOld, foundActive bool
	for _, art := range res.Artifacts {
		if art.ProjectName == "old-app" {
			foundOld = true
			if !art.SafeToDelete {
				t.Errorf("old-app node_modules should be marked SafeToDelete")
			}
			if art.ArtifactType != "node_modules" {
				t.Errorf("Expected artifactType node_modules, got %s", art.ArtifactType)
			}
		}
		if art.ProjectName == "active-app" {
			foundActive = true
			if art.SafeToDelete {
				t.Errorf("active-app node_modules should NOT be marked SafeToDelete")
			}
		}
	}

	if !foundOld || !foundActive {
		t.Errorf("Both projects should have been discovered. Old: %v, Active: %v", foundOld, foundActive)
	}
}
