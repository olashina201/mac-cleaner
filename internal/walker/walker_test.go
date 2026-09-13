package walker

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
)

func TestConcurrentWalker(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "walker_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create a nested file structure:
	// tempDir/
	//   file1.txt
	//   sub1/
	//     file2.txt
	//     sub2/
	//       file3.txt
	//   skip_me/
	//     file4.txt
	if err := os.WriteFile(filepath.Join(tempDir, "file1.txt"), []byte("hello"), 0644); err != nil {
		t.Fatal(err)
	}
	sub1 := filepath.Join(tempDir, "sub1")
	sub2 := filepath.Join(sub1, "sub2")
	skipDir := filepath.Join(tempDir, "skip_me")
	if err := os.MkdirAll(sub2, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(skipDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub1, "file2.txt"), []byte("world"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub2, "file3.txt"), []byte("nested"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(skipDir, "file4.txt"), []byte("skip"), 0644); err != nil {
		t.Fatal(err)
	}

	w := New(WalkOptions{
		MaxWorkers: 4,
		SkipDir: func(path string) bool {
			return filepath.Base(path) == "skip_me"
		},
	})

	var mu sync.Mutex
	found := make(map[string]int64)
	var count int64

	err = w.Walk(context.Background(), tempDir, func(path string, d fs.DirEntry, info fs.FileInfo) error {
		atomic.AddInt64(&count, 1)
		mu.Lock()
		found[filepath.Base(path)] = info.Size()
		mu.Unlock()
		return nil
	})

	if err != nil {
		t.Fatalf("Walk returned unexpected error: %v", err)
	}

	if count != 3 {
		t.Fatalf("Expected 3 files, got %d. Found: %+v", count, found)
	}

	for _, name := range []string{"file1.txt", "file2.txt", "file3.txt"} {
		if _, ok := found[name]; !ok {
			t.Errorf("Expected file %s was not found", name)
		}
	}
	if _, ok := found["file4.txt"]; ok {
		t.Errorf("file4.txt should have been skipped")
	}
}
