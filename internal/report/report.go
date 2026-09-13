package report

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"maccleaner/internal/scanner"
)

// FormatBytes converts a byte count into a human-readable string (e.g., "1.42 GB").
func FormatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	units := []string{"KB", "MB", "GB", "TB", "PB"}
	return fmt.Sprintf("%.2f %s", float64(b)/float64(div), units[exp])
}

// FormatDuration formats a duration for display.
func FormatDuration(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	return fmt.Sprintf("%.2fs", d.Seconds())
}

// PrintJunkReport renders a structured table of junk scan findings to w (defaults to os.Stdout).
func PrintJunkReport(w io.Writer, res *scanner.JunkScanResult, verbose bool) {
	if w == nil {
		w = os.Stdout
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "=========================================================================================")
	fmt.Fprintf(w, "                        maccleaner - Junk & Cache Scan Report\n")
	fmt.Fprintf(w, "                        Age Threshold: > %d days (Safe to delete)\n", res.ThresholdDays)
	fmt.Fprintln(w, "=========================================================================================")
	fmt.Fprintln(w)

	tw := tabwriter.NewWriter(w, 2, 4, 3, ' ', 0)
	fmt.Fprintln(tw, "CATEGORY\tTARGET PATTERN\tTOTAL FILES\tTOTAL SIZE\tSAFE TO DELETE\tRECLAIMABLE")
	fmt.Fprintln(tw, "--------\t--------------\t-----------\t----------\t--------------\t-----------")

	for _, cat := range res.Categories {
		status := fmt.Sprintf("%d files", cat.CandidateCount)
		reclaimable := FormatBytes(cat.CandidateSize)
		if cat.ListOnly {
			status = "Review only"
			reclaimable = "(excluded)"
		} else if len(cat.MatchedPaths) == 0 {
			status = "Not found"
			reclaimable = "-"
		}

		fmt.Fprintf(tw, "%s\t%s\t%d\t%s\t%s\t%s\n",
			cat.Name,
			cat.Pattern,
			cat.TotalFiles,
			FormatBytes(cat.TotalSize),
			status,
			reclaimable,
		)
	}
	tw.Flush()

	fmt.Fprintln(w)
	fmt.Fprintln(w, "-----------------------------------------------------------------------------------------")
	fmt.Fprintf(w, "Summary:\n")
	fmt.Fprintf(w, "  • Total Scanned:       %d files (%s)\n", res.TotalFiles, FormatBytes(res.TotalSize))
	fmt.Fprintf(w, "  • Reclaimable Space:   %d files (%s)\n", res.CandidateCount, FormatBytes(res.CandidateSize))
	fmt.Fprintf(w, "  • Scan Duration:       %s\n", FormatDuration(res.ScanDuration))
	fmt.Fprintln(w, "-----------------------------------------------------------------------------------------")
	fmt.Fprintln(w, "[NOTICE] DRY-RUN MODE: No files were touched or deleted.")
	fmt.Fprintln(w, "[NOTE]   ~/Downloads is listed for review only and is never automatically flagged.")
	fmt.Fprintln(w)

	if verbose && len(res.Candidates) > 0 {
		// Sort candidates by size descending
		sorted := make([]scanner.JunkItem, len(res.Candidates))
		copy(sorted, res.Candidates)
		sort.Slice(sorted, func(i, j int) bool {
			return sorted[i].Size > sorted[j].Size
		})

		fmt.Fprintln(w, "Top Reclaimable Files (Sorted by Size):")
		fmt.Fprintln(w, "-----------------------------------------------------------------------------------------")
		vtw := tabwriter.NewWriter(w, 2, 4, 3, ' ', 0)
		fmt.Fprintln(vtw, "SIZE\tCATEGORY\tMODIFIED\tPATH")
		fmt.Fprintln(vtw, "----\t--------\t--------\t----")

		limit := 30
		if len(sorted) < limit {
			limit = len(sorted)
		}
		for i := 0; i < limit; i++ {
			item := sorted[i]
			if item.ListOnly {
				continue
			}
			daysAgo := int(time.Since(item.ModTime).Hours() / 24)
			fmt.Fprintf(vtw, "%s\t%s\t%dd ago\t%s\n",
				FormatBytes(item.Size),
				item.Category,
				daysAgo,
				abbreviatePath(item.Path),
			)
		}
		vtw.Flush()
		if len(sorted) > limit {
			fmt.Fprintf(w, "\n... and %d more files (use filters or inspect category directories).\n", len(sorted)-limit)
		}
		fmt.Fprintln(w)
	}
}

// PrintDevReport renders a structured table of developer artifact findings.
func PrintDevReport(w io.Writer, res *scanner.DevScanResult, verbose bool) {
	if w == nil {
		w = os.Stdout
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "=========================================================================================")
	fmt.Fprintf(w, "                   maccleaner - Developer Project & Artifact Report\n")
	fmt.Fprintf(w, "                   Inactivity Threshold: > %d days (Safe to delete)\n", res.ThresholdDays)
	fmt.Fprintln(w, "=========================================================================================")
	fmt.Fprintln(w)

	if len(res.Artifacts) == 0 {
		fmt.Fprintln(w, "No developer build artifacts or node_modules found in search paths.")
		fmt.Fprintf(w, "Search roots: %s\n\n", strings.Join(res.SearchRoots, ", "))
		return
	}

	tw := tabwriter.NewWriter(w, 2, 4, 3, ' ', 0)
	fmt.Fprintln(tw, "PROJECT\tTYPE\tINACTIVE\tSIZE\tSTATUS\tPATH")
	fmt.Fprintln(tw, "-------\t----\t--------\t----\t------\t----")

	// Sort artifacts: safe to delete first, then by size descending
	sorted := make([]scanner.DevArtifact, len(res.Artifacts))
	copy(sorted, res.Artifacts)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].SafeToDelete != sorted[j].SafeToDelete {
			return sorted[i].SafeToDelete
		}
		return sorted[i].Size > sorted[j].Size
	})

	for _, art := range sorted {
		status := "Active (Skip)"
		if art.SafeToDelete {
			status = "Safe to delete"
		}
		fmt.Fprintf(tw, "%s\t%s\t%dd ago\t%s\t%s\t%s\n",
			art.ProjectName,
			art.ArtifactType,
			art.DaysInactive,
			FormatBytes(art.Size),
			status,
			abbreviatePath(art.Path),
		)
	}
	tw.Flush()

	fmt.Fprintln(w)
	fmt.Fprintln(w, "-----------------------------------------------------------------------------------------")
	fmt.Fprintf(w, "Summary:\n")
	fmt.Fprintf(w, "  • Total Projects Found:   %d (%s total dependencies/artifacts)\n", len(res.Artifacts), FormatBytes(res.TotalSize))
	fmt.Fprintf(w, "  • Inactive Projects:      %d (%s reclaimable space)\n", res.CandidateCount, FormatBytes(res.CandidateSize))
	fmt.Fprintf(w, "  • Scan Duration:          %s\n", FormatDuration(res.ScanDuration))
	fmt.Fprintln(w, "-----------------------------------------------------------------------------------------")
	fmt.Fprintln(w, "[NOTICE] DRY-RUN MODE: No files or directories were deleted.")
	fmt.Fprintln(w, "[TIP]    Deleted node_modules can be restored anytime with 'npm install' or 'pnpm install'.")
	fmt.Fprintln(w)
}

// abbreviatePath shortens user home directory to ~ for cleaner terminal output.
func abbreviatePath(path string) string {
	home, err := os.UserHomeDir()
	if err == nil && strings.HasPrefix(path, home) {
		return "~" + strings.TrimPrefix(path, home)
	}
	return path
}

