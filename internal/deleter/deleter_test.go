package deleter

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDeleterDenyList(t *testing.T) {
	d, err := New()
	if err != nil {
		t.Fatalf("Failed to create deleter: %v", err)
	}

	blocked := []string{
		"/",
		"/System",
		"/System/Library",
		"/usr/bin",
		"/usr/local/bin",
		"/bin/sh",
		"/sbin/fsck",
		"/private/var/db",
		"/private/etc/hosts",
		"/Applications/Safari.app",
		d.HomeDir,
	}

	for _, path := range blocked {
		if !d.IsDenied(path) {
			t.Errorf("Path %s should have been DENIED by deny-list", path)
		}
	}

	allowed := filepath.Join(d.HomeDir, "Library/Caches/com.test.app/cache.tmp")
	if d.IsDenied(allowed) {
		t.Errorf("Path %s should be allowed", allowed)
	}
}

func TestDeleterDryRun(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "maccleaner_del_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	testFile := filepath.Join(tempDir, "sample.cache")
	if err := os.WriteFile(testFile, []byte("some junk data"), 0644); err != nil {
		t.Fatal(err)
	}

	d, err := New()
	if err != nil {
		t.Fatal(err)
	}

	candidates := []DeleteCandidate{
		{
			Path:     testFile,
			Size:     int64(len("some junk data")),
			Category: "Test",
		},
	}

	res, err := d.DeleteBatch(candidates, true) // dry-run
	if err != nil {
		t.Fatalf("DeleteBatch failed: %v", err)
	}

	if res.DeletedCount != 1 {
		t.Errorf("Expected 1 candidate flagged in dry-run, got %d", res.DeletedCount)
	}

	// Verify file was NOT removed
	if _, err := os.Stat(testFile); os.IsNotExist(err) {
		t.Error("File was deleted during dry-run!")
	}
}

func TestDeleterAuditLog(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "maccleaner_audit_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	d := &Deleter{
		HomeDir:     tempDir,
		AuditLogDir: filepath.Join(tempDir, ".maccleaner"),
		LogFile:     filepath.Join(tempDir, ".maccleaner", "deletions.log"),
	}

	if err := os.MkdirAll(d.AuditLogDir, 0755); err != nil {
		t.Fatal(err)
	}

	target := filepath.Join(tempDir, "to_delete.tmp")
	if err := os.WriteFile(target, []byte("delete me"), 0644); err != nil {
		t.Fatal(err)
	}

	candidates := []DeleteCandidate{
		{
			Path:     target,
			Size:     int64(len("delete me")),
			Category: "Temp",
		},
	}

	res, err := d.DeleteBatch(candidates, false)
	if err != nil {
		t.Fatalf("DeleteBatch failed: %v", err)
	}
	if res.DeletedCount != 1 {
		t.Errorf("Expected 1 deleted item, got %d", res.DeletedCount)
	}

	// Verify audit log exists and contains entry
	logData, err := os.ReadFile(d.LogFile)
	if err != nil {
		t.Fatalf("Audit log not written: %v", err)
	}
	if !strings.Contains(string(logData), "to_delete.tmp") {
		t.Errorf("Expected to_delete.tmp in audit log, got:\n%s", string(logData))
	}
}
