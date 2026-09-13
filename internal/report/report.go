package report

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/charmbracelet/lipgloss"

	"maccleaner/internal/scanner"
)

// Styles
var (
	BrandPurple = lipgloss.Color("#7D56F4")
	AccentCyan  = lipgloss.Color("#04D9FF")
	GreenAccent = lipgloss.Color("#00F5D4")
	AmberWarn   = lipgloss.Color("#FFBE0B")
	MutedGray   = lipgloss.Color("#718096")
	PureWhite   = lipgloss.Color("#FFFFFF")

	ReportHeaderStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(PureWhite).
				Background(BrandPurple).
				Padding(0, 2)

	SubHeaderStyle = lipgloss.NewStyle().
			Foreground(AccentCyan).
			Bold(true)

	SummaryBoxStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(BrandPurple).
			Padding(0, 1)

	DryRunBadge = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#000000")).
			Background(AmberWarn).
			Padding(0, 1)

	SafeBadge = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#000000")).
			Background(GreenAccent).
			Padding(0, 1)

	ReviewBadge = lipgloss.NewStyle().
			Foreground(MutedGray).
			Italic(true)
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

// PrintJunkReport renders a structured, colorized table of junk scan findings.
func PrintJunkReport(w io.Writer, res *scanner.JunkScanResult, verbose bool) {
	if w == nil {
		w = os.Stdout
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, ReportHeaderStyle.Render("🧹 maccleaner - Junk & Cache Scan Report"))
	fmt.Fprintf(w, "   %s > %d days (Safe to delete)\n\n",
		lipgloss.NewStyle().Foreground(AccentCyan).Render("Age Threshold:"),
		res.ThresholdDays,
	)

	tw := tabwriter.NewWriter(w, 2, 4, 3, ' ', 0)
	headerCategory := lipgloss.NewStyle().Bold(true).Foreground(PureWhite).Render("CATEGORY")
	headerPattern := lipgloss.NewStyle().Bold(true).Foreground(MutedGray).Render("TARGET PATTERN")
	headerScanned := lipgloss.NewStyle().Bold(true).Foreground(AccentCyan).Render("TOTAL FILES")
	headerSize := lipgloss.NewStyle().Bold(true).Foreground(AccentCyan).Render("TOTAL SIZE")
	headerSafe := lipgloss.NewStyle().Bold(true).Foreground(GreenAccent).Render("SAFE TO DELETE")
	headerReclaimable := lipgloss.NewStyle().Bold(true).Foreground(GreenAccent).Render("RECLAIMABLE")

	fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
		headerCategory, headerPattern, headerScanned, headerSize, headerSafe, headerReclaimable)
	fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
		"--------", "--------------", "-----------", "----------", "--------------", "-----------")

	for _, cat := range res.Categories {
		var statusStr, reclaimableStr string

		if cat.ListOnly {
			statusStr = ReviewBadge.Render("Review only")
			reclaimableStr = lipgloss.NewStyle().Foreground(MutedGray).Render("(excluded)")
		} else if len(cat.MatchedPaths) == 0 {
			statusStr = lipgloss.NewStyle().Foreground(MutedGray).Render("Not found")
			reclaimableStr = "-"
		} else {
			statusStr = lipgloss.NewStyle().Foreground(GreenAccent).Render(fmt.Sprintf("%d files", cat.CandidateCount))
			reclaimableStr = lipgloss.NewStyle().Foreground(GreenAccent).Bold(true).Render(FormatBytes(cat.CandidateSize))
		}

		catName := lipgloss.NewStyle().Bold(true).Render(cat.Name)
		patStr := lipgloss.NewStyle().Foreground(MutedGray).Render(cat.Pattern)
		totFiles := fmt.Sprintf("%d", cat.TotalFiles)
		totSize := FormatBytes(cat.TotalSize)

		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
			catName, patStr, totFiles, totSize, statusStr, reclaimableStr)
	}
	tw.Flush()

	fmt.Fprintln(w)
	// Summary Card
	summaryContent := fmt.Sprintf(
		"📊 Summary:\n"+
			"  • Total Scanned:       %s files (%s)\n"+
			"  • Reclaimable Space:   %s (%s)\n"+
			"  • Scan Duration:       %s",
		lipgloss.NewStyle().Bold(true).Foreground(AccentCyan).Render(fmt.Sprintf("%d", res.TotalFiles)),
		FormatBytes(res.TotalSize),
		lipgloss.NewStyle().Bold(true).Foreground(GreenAccent).Render(fmt.Sprintf("%d files", res.CandidateCount)),
		lipgloss.NewStyle().Bold(true).Foreground(GreenAccent).Render(FormatBytes(res.CandidateSize)),
		FormatDuration(res.ScanDuration),
	)
	fmt.Fprintln(w, SummaryBoxStyle.Render(summaryContent))
	fmt.Fprintln(w)

	notice := fmt.Sprintf("%s %s\n%s  %s\n",
		DryRunBadge.Render("NOTICE"),
		lipgloss.NewStyle().Foreground(AmberWarn).Render("DRY-RUN MODE: No files were touched or deleted."),
		lipgloss.NewStyle().Foreground(MutedGray).Render("[NOTE]"),
		lipgloss.NewStyle().Foreground(MutedGray).Render("~/Downloads is listed for review only and is never automatically flagged."),
	)
	fmt.Fprintln(w, notice)

	if verbose && len(res.Candidates) > 0 {
		sorted := make([]scanner.JunkItem, len(res.Candidates))
		copy(sorted, res.Candidates)
		sort.Slice(sorted, func(i, j int) bool {
			return sorted[i].Size > sorted[j].Size
		})

		fmt.Fprintln(w, SubHeaderStyle.Render("Top Reclaimable Files (Sorted by Size):"))
		fmt.Fprintln(w, strings.Repeat("─", 78))
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
				lipgloss.NewStyle().Foreground(GreenAccent).Bold(true).Render(FormatBytes(item.Size)),
				item.Category,
				daysAgo,
				lipgloss.NewStyle().Foreground(MutedGray).Render(abbreviatePath(item.Path)),
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
	fmt.Fprintln(w, ReportHeaderStyle.Render("💻 maccleaner - Developer Project & Artifact Report"))
	fmt.Fprintf(w, "   %s > %d days (Safe to delete)\n\n",
		lipgloss.NewStyle().Foreground(AccentCyan).Render("Inactivity Threshold:"),
		res.ThresholdDays,
	)

	if len(res.Artifacts) == 0 {
		fmt.Fprintln(w, lipgloss.NewStyle().Foreground(GreenAccent).Render("✨ No developer build artifacts or dormant node_modules found."))
		fmt.Fprintf(w, "Search roots: %s\n\n", strings.Join(res.SearchRoots, ", "))
		return
	}

	tw := tabwriter.NewWriter(w, 2, 4, 3, ' ', 0)
	fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
		lipgloss.NewStyle().Bold(true).Foreground(PureWhite).Render("PROJECT"),
		lipgloss.NewStyle().Bold(true).Foreground(AccentCyan).Render("TYPE"),
		lipgloss.NewStyle().Bold(true).Foreground(MutedGray).Render("INACTIVE"),
		lipgloss.NewStyle().Bold(true).Foreground(GreenAccent).Render("SIZE"),
		lipgloss.NewStyle().Bold(true).Foreground(AmberWarn).Render("STATUS"),
		lipgloss.NewStyle().Bold(true).Foreground(MutedGray).Render("PATH"),
	)
	fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
		"-------", "----", "--------", "----", "------", "----")

	sorted := make([]scanner.DevArtifact, len(res.Artifacts))
	copy(sorted, res.Artifacts)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].SafeToDelete != sorted[j].SafeToDelete {
			return sorted[i].SafeToDelete
		}
		return sorted[i].Size > sorted[j].Size
	})

	for _, art := range sorted {
		status := lipgloss.NewStyle().Foreground(MutedGray).Render("Active (Skip)")
		if art.SafeToDelete {
			status = SafeBadge.Render("SAFE TO DELETE")
		}
		sizeStr := lipgloss.NewStyle().Foreground(GreenAccent).Bold(true).Render(FormatBytes(art.Size))
		projName := lipgloss.NewStyle().Bold(true).Render(art.ProjectName)
		typeStr := lipgloss.NewStyle().Foreground(AccentCyan).Render(art.ArtifactType)
		pathStr := lipgloss.NewStyle().Foreground(MutedGray).Render(abbreviatePath(art.Path))

		fmt.Fprintf(tw, "%s\t%s\t%dd ago\t%s\t%s\t%s\n",
			projName,
			typeStr,
			art.DaysInactive,
			sizeStr,
			status,
			pathStr,
		)
	}
	tw.Flush()

	fmt.Fprintln(w)
	summaryContent := fmt.Sprintf(
		"📊 Summary:\n"+
			"  • Total Projects Found:   %s (%s total dependencies/artifacts)\n"+
			"  • Inactive Projects:      %s (%s reclaimable space)\n"+
			"  • Scan Duration:          %s",
		lipgloss.NewStyle().Bold(true).Foreground(AccentCyan).Render(fmt.Sprintf("%d", len(res.Artifacts))),
		FormatBytes(res.TotalSize),
		lipgloss.NewStyle().Bold(true).Foreground(GreenAccent).Render(fmt.Sprintf("%d projects", res.CandidateCount)),
		lipgloss.NewStyle().Bold(true).Foreground(GreenAccent).Render(FormatBytes(res.CandidateSize)),
		FormatDuration(res.ScanDuration),
	)
	fmt.Fprintln(w, SummaryBoxStyle.Render(summaryContent))
	fmt.Fprintln(w)

	notice := fmt.Sprintf("%s %s\n%s   %s\n",
		DryRunBadge.Render("NOTICE"),
		lipgloss.NewStyle().Foreground(AmberWarn).Render("DRY-RUN MODE: No files or directories were deleted."),
		lipgloss.NewStyle().Foreground(AccentCyan).Render("[TIP]"),
		lipgloss.NewStyle().Foreground(PureWhite).Render("Deleted node_modules can be restored anytime with 'npm install' or 'pnpm install'."),
	)
	fmt.Fprintln(w, notice)
}

// abbreviatePath shortens user home directory to ~ for cleaner terminal output.
func abbreviatePath(path string) string {
	home, err := os.UserHomeDir()
	if err == nil && strings.HasPrefix(path, home) {
		return "~" + strings.TrimPrefix(path, home)
	}
	return path
}
