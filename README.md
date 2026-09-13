# maccleaner 🧹

A fast, safe, and free personal macOS disk cleanup utility written in Go. Designed as a lightweight, transparent alternative to paid disk cleanup utilities like CleanMyMac — compiled into a single static binary with zero external runtime dependencies.

---

## Features

- ⚡ **High-Performance Concurrent Walker**: Crawls directory trees concurrently using a worker pool bounded by `runtime.NumCPU() * 2` with dynamic dispatching to eliminate deadlock and avoid unbounded memory consumption.
- 🗑️ **Intelligent Junk & Cache Scanner**:
  - Scans user caches, app support caches, system and user logs, temporary folders, Xcode DerivedData/Archives, and sandboxed container caches.
  - Expands `~` home directories and wildcard paths (`filepath.Glob`).
  - Flags files as safe-to-delete only if older than a configurable threshold (default: **30 days**).
  - Explicit **List-Only protection** for sensitive directories like `~/Downloads` (never flagged for deletion).
- 🔒 **Safety-First Architecture**:
  - **Dry-run by default**: No files are modified or deleted unless explicitly requested.
  - **macOS Trash integration**: Deletions move files to `~/.Trash` instead of permanent unrecoverable removal.
  - **Hardcoded Deny-List**: Critical system paths (`/System`, `/usr`, `/bin`, `/sbin`, `/private/var/db`, and SIP-protected areas) can never be touched under any circumstances.
  - **Audit Logging**: Every deletion is recorded with path, size, and timestamp in `~/.maccleaner/deletions.log`.
- 📊 **Clear Terminal Reports**: Generates structured summary tables displaying total scanned space vs. reclaimable space per category with human-readable byte sizes.

---

## Project Structure

```
maccleaner/
├── cmd/
│   └── maccleaner/
│       └── main.go              # Cobra CLI entrypoint
├── internal/
│   ├── walker/
│   │   ├── walker.go            # Concurrent bounded directory walker
│   │   └── walker_test.go       # Walker test suite
│   ├── scanner/
│   │   ├── junk.go              # Cache, log, and temp file scanner
│   │   ├── junk_test.go         # Junk scanner test suite
│   │   ├── bigfiles.go          # [Planned] Size-threshold large file finder
│   │   └── duplicates.go        # [Planned] Three-pass fast duplicate finder
│   ├── report/
│   │   └── report.go            # Tabular terminal reporting and formatters
│   └── deleter/
│       └── deleter.go           # [Planned] Safe Trash deletion, deny-list, audit log
├── go.mod
├── go.sum
└── README.md
```

---

## Installation & Building

### Prerequisites
- macOS (Apple Silicon or Intel)
- Go 1.22+

### Build from source
```bash
git clone https://github.com/your-username/maccleaner.git
cd maccleaner
go build -o bin/maccleaner ./cmd/maccleaner
```

---

## Usage

### 1. Scan for Junk & Caches
Scans default macOS cache and log locations with a 30-day age threshold:
```bash
./bin/maccleaner scan junk
```

Example output:
```
🔍 Scanning junk & cache locations (age threshold: > 30 days)...

=========================================================================================
                        maccleaner - Junk & Cache Scan Report
                        Age Threshold: > 30 days (Safe to delete)
=========================================================================================

CATEGORY               TARGET PATTERN                               TOTAL FILES   TOTAL SIZE   SAFE TO DELETE   RECLAIMABLE
--------               --------------                               -----------   ----------   --------------   -----------
User Caches            ~/Library/Caches                             133620        4.17 GB      52591 files      1.60 GB
User Logs              ~/Library/Logs                               0             0 B          0 files          0 B
App Support Caches     ~/Library/Application Support/*/Cache        3110          327.25 MB    2987 files       303.02 MB
System Logs            /private/var/log                             0             0 B          0 files          0 B
Temporary Files        /private/var/folders/*/*/T                   0             0 B          Not found        -
Xcode DerivedData      ~/Library/Developer/Xcode/DerivedData        0             0 B          0 files          0 B
Xcode Archives         ~/Library/Developer/Xcode/Archives           0             0 B          0 files          0 B
App Container Caches   ~/Library/Containers/*/Data/Library/Caches   0             0 B          Not found        -
Downloads              ~/Downloads                                  0             0 B          Review only      (excluded)

-----------------------------------------------------------------------------------------
Summary:
  • Total Scanned:       136730 files (4.49 GB)
  • Reclaimable Space:   55578 files (1.90 GB)
  • Scan Duration:       2.03s
-----------------------------------------------------------------------------------------
[NOTICE] DRY-RUN MODE: No files were touched or deleted.
[NOTE]   ~/Downloads is listed for review only and is never automatically flagged.
```

### 2. Custom Age Threshold
Target files older than 60 days:
```bash
./bin/maccleaner scan junk --threshold-days 60
```

### 3. Verbose Mode
List the largest individual candidate files identified:
```bash
./bin/maccleaner scan junk -v
```

### 4. Developer Artifacts & Stale `node_modules` (`maccleaner scan dev`)
Deep-scans project workspaces (`~/Projects`, `~/Developer`, `~/Documents/projects`, or custom paths) for dormant build artifacts:
- **`node_modules`** in inactive JavaScript/TypeScript projects
- **`.next`** build caches in Next.js projects
- **`target`** build directories in Rust projects (`Cargo.toml`)
- **`venv` / `.venv`** in Python projects

```bash
# Scan default developer project roots for artifacts inactive > 30 days
./bin/maccleaner scan dev

# Target a specific workspace with custom inactivity threshold (e.g. 60 days)
./bin/maccleaner scan dev --path ~/Documents/projects --threshold-days 60
```

### 5. Interactive Review & Clean (`maccleaner clean`)
By default, `maccleaner` protects your system with **dry-run** mode. When cleaning, you can interactively choose what to delete directly in the terminal:

```bash
# Interactive selection mode (system caches & logs)
./bin/maccleaner clean

# Deep clean mode (includes dormant node_modules and developer build caches)
./bin/maccleaner clean --deep

# Dry-run clean (simulates deletion and displays what would be removed)
./bin/maccleaner clean --dry-run
./bin/maccleaner clean --deep --dry-run

# Non-interactive / batch clean with explicit confirmation
./bin/maccleaner clean --yes
./bin/maccleaner clean --deep --yes
```

#### Interactive Terminal Selection
Instead of blindly purging files, `maccleaner clean` provides an interactive menu:
- **Browse Categories**: Inspect individual categories (User Caches, Xcode DerivedData, Dormant `node_modules`, etc.).
- **Choose What to Clean**: Enter category numbers (e.g. `1,3`), `a` for all, or `q` to quit.
- **Recoverable Deletion**: Selected folders and files are safely moved to `~/.Trash` (never `rm -rf`).
- **100% Reversible**: Projects remain intact. Any deleted `node_modules` can be reinstalled anytime with `npm install` or `pnpm install`.

---

## Safe Deletion Guarantees

1. **Dry-Run by Default**: Unless `--yes` is passed or explicitly confirmed in the interactive prompt, nothing on your disk is touched.
2. **Move to Trash (Never `rm -rf`)**: Files are relocated to macOS `~/.Trash` (via Finder / macOS AppleEvents API), meaning you can restore any file with "Put Back" in macOS Finder.
3. **Hardcoded Deny-List**: Under no circumstances can files in protected system directories be touched:
   - `/System`
   - `/usr`, `/bin`, `/sbin`
   - `/private/var/db`
   - System Integrity Protection (SIP) protected directories
4. **Local Audit Trail**: Every deleted file is recorded in `~/.maccleaner/deletions.log` with original timestamp, path, and size.

---

## Testing

Run the full automated test suite:
```bash
go test -v ./...
```

---

## Roadmap

- [x] **Step 1**: Shared concurrent walker + junk scanner + dry-run text report
- [ ] **Step 2**: Big-file finder reusing the concurrent walker (`maccleaner scan bigfiles --threshold 500MB`)
- [ ] **Step 3**: Three-pass fast duplicate finder (Exact Size $\rightarrow$ xxhash64 Partial $\rightarrow$ SHA-256 Full)
- [ ] **Step 4**: Safe deletion layer (`~/.Trash` move, hardcoded deny-list, `~/.maccleaner/deletions.log` audit trail)
- [ ] **Step 5**: Interactive terminal UI with Charm `bubbletea` + `lipgloss` for reviewing and selecting files to delete

---

## License

MIT

