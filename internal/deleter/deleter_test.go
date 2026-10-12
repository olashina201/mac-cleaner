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

func TestDeleterParallelBatch(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "maccleaner_parallel_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	d := &Deleter{
		HomeDir:     tempDir,
		AuditLogDir: filepath.Join(tempDir, ".maccleaner"),
		LogFile:     filepath.Join(tempDir, ".maccleaner", "deletions.log"),
		Workers:     8,
	}

	const n = 50
	var candidates []DeleteCandidate
	for i := 0; i < n; i++ {
		p := filepath.Join(tempDir, "batchfile_"+strings.Repeat(string(rune('a'+i%26)), 2)+"_"+string(rune('0'+(i/26)%10))+string(rune('0'+i%10))+".tmp")
		if err := os.WriteFile(p, []byte("junk"), 0644); err != nil {
			t.Fatal(err)
		}
		candidates = append(candidates, DeleteCandidate{Path: p, Size: 4, Category: "Test"})
	}

	var progressCalls int64
	res, err := d.DeleteBatchWithProgress(candidates, false, func(done, total int64) {
		progressCalls++
	})
	if err != nil {
		t.Fatalf("DeleteBatch failed: %v", err)
	}
	if res.DeletedCount != n {
		t.Errorf("Expected %d deleted, got %d (skipped %d, errors %v)", n, res.DeletedCount, res.SkippedCount, res.Errors)
	}
	if res.PermissionDeniedCount != 0 {
		t.Errorf("Expected 0 permission-denied, got %d", res.PermissionDeniedCount)
	}
	// All originals should be gone (moved to temp Trash).
	for _, c := range candidates {
		if _, err := os.Lstat(c.Path); !os.IsNotExist(err) {
			t.Errorf("Expected %s to be trashed", c.Path)
		}
	}
	if progressCalls == 0 {
		t.Error("Expected progress callback to be invoked")
	}
}

func TestDeleterSkipsUnwritableWithoutPrompt(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission-bit precheck is bypassed when running as root")
	}
	tempDir, err := os.MkdirTemp("", "maccleaner_perm_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = os.Chmod(filepath.Join(tempDir, "locked"), 0755)
		os.RemoveAll(tempDir)
	}()

	d := &Deleter{
		HomeDir:     tempDir,
		AuditLogDir: filepath.Join(tempDir, ".maccleaner"),
		LogFile:     filepath.Join(tempDir, ".maccleaner", "deletions.log"),
	}

	lockedDir := filepath.Join(tempDir, "locked")
	if err := os.MkdirAll(lockedDir, 0755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(lockedDir, "root_owned.tmp")
	if err := os.WriteFile(target, []byte("nope"), 0644); err != nil {
		t.Fatal(err)
	}
	// Remove write permission on the parent: rename is doomed without
	// elevation, so the deleter must skip it upfront with no auth prompt.
	if err := os.Chmod(lockedDir, 0555); err != nil {
		t.Fatal(err)
	}

	res, err := d.DeleteBatch([]DeleteCandidate{{Path: target, Size: 4, Category: "Test"}}, false)
	if err != nil {
		t.Fatalf("DeleteBatch failed: %v", err)
	}
	if res.PermissionDeniedCount != 1 {
		t.Errorf("Expected 1 permission-denied skip, got %d (errors %v)", res.PermissionDeniedCount, res.Errors)
	}
	if res.DeletedCount != 0 {
		t.Errorf("Expected 0 deleted, got %d", res.DeletedCount)
	}
	if _, err := os.Lstat(target); err != nil {
		t.Errorf("Unwritable file should be left in place, stat err: %v", err)
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
