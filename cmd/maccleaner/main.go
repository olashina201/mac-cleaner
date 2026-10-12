package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"

	"maccleaner/internal/deleter"
	"maccleaner/internal/report"
	"maccleaner/internal/scanner"
	"maccleaner/internal/ui"
)

var (
	thresholdDays int
	dryRun        bool
	autoConfirm   bool
	verbose       bool
	deepScan      bool
	scanPath      string
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	rootCmd := &cobra.Command{
		Use:   "maccleaner",
		Short: "maccleaner is a safe, high-performance macOS disk cleanup tool",
		Long: `maccleaner is a free, fast, and safe disk cleanup utility for macOS.
It scans and cleans caches, logs, developer junk, big files, and duplicate files.`,
	}

	scanCmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan macOS system for junk, dev artifacts, big files, or duplicates",
	}

	// 1. scan junk
	scanJunkCmd := &cobra.Command{
		Use:   "junk",
		Short: "Report cache, log, and temporary junk files",
		Long: `Scans standard macOS cache, log, temporary, Xcode, and container directories.
Only items older than the specified age threshold (default 30 days) are flagged
as safe-to-delete candidates.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Printf("🔍 Scanning junk & cache locations (age threshold: > %d days)...\n", thresholdDays)

			junkScanner := scanner.NewJunkScanner(nil, thresholdDays)
			res, err := junkScanner.Scan(ctx)
			if err != nil {
				return fmt.Errorf("scan failed: %w", err)
			}

			report.PrintJunkReport(os.Stdout, res, verbose)
			return nil
		},
	}

	scanJunkCmd.Flags().IntVarP(&thresholdDays, "threshold-days", "t", 30, "Age threshold in days for safe-to-delete files")
	scanJunkCmd.Flags().BoolVar(&dryRun, "dry-run", true, "Perform scan in dry-run mode (default true)")
	scanJunkCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Show detailed list of candidate files")

	// 2. scan dev
	scanDevCmd := &cobra.Command{
		Use:   "dev",
		Short: "Scan for dormant node_modules and developer build artifacts",
		Long: `Performs deep scanning across project folders to identify unused node_modules,
.next caches, Rust target directories, and Python virtual environments older than
the configured inactivity threshold (default 30 days).`,
		RunE: func(cmd *cobra.Command, args []string) error {
			var roots []string
			if scanPath != "" {
				roots = []string{scanPath}
			}
			devScanner := scanner.NewDevScanner(roots, thresholdDays)
			fmt.Printf("🔍 Scanning developer workspaces for dormant artifacts (inactive > %d days)...\n", thresholdDays)
			fmt.Printf("   Search roots: %s\n", strings.Join(devScanner.SearchRoots, ", "))

			res, err := devScanner.Scan(ctx)
			if err != nil {
				return fmt.Errorf("dev scan failed: %w", err)
			}

			report.PrintDevReport(os.Stdout, res, verbose)
			return nil
		},
	}

	scanDevCmd.Flags().IntVarP(&thresholdDays, "threshold-days", "t", 30, "Inactivity threshold in days for safe-to-delete artifacts")
	scanDevCmd.Flags().StringVarP(&scanPath, "path", "p", "", "Custom project directory or root path to scan")
	scanDevCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Show detailed file breakdown")

	// Planned subcommands for subsequent phases
	scanBigFilesCmd := &cobra.Command{
		Use:   "bigfiles",
		Short: "Scan for large files over a size threshold (Step 2)",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("Feature 'bigfiles' is planned for Step 2.")
			return nil
		},
	}

	scanDuplicatesCmd := &cobra.Command{
		Use:   "duplicates",
		Short: "Scan for duplicate files using multi-pass hashing (Step 3)",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("Feature 'duplicates' is planned for Step 3.")
			return nil
		},
	}

	scanAllCmd := &cobra.Command{
		Use:   "all",
		Short: "Run all scanners and provide a unified report",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := scanJunkCmd.RunE(cmd, args); err != nil {
				return err
			}
			return scanDevCmd.RunE(cmd, args)
		},
	}

	cleanCmd := &cobra.Command{
		Use:   "clean",
		Short: "Safe deletion with Trash integration, deny-list, and audit log",
		Long: `Interactively reviews or deletes safe-to-delete candidate files and dormant project artifacts.
Files are relocated to ~/.Trash (recoverable via Finder) and logged to ~/.maccleaner/deletions.log.
Protected system directories are strictly blocked by the deny-list.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runClean(ctx, cmd)
		},
	}

	cleanCmd.Flags().BoolVar(&dryRun, "dry-run", false, "Simulate cleaning without moving files to ~/.Trash")
	cleanCmd.Flags().BoolVarP(&autoConfirm, "yes", "y", false, "Skip interactive confirmation and move all safe candidates to ~/.Trash")
	cleanCmd.Flags().IntVarP(&thresholdDays, "threshold-days", "t", 30, "Age threshold in days for safe-to-delete items")
	cleanCmd.Flags().BoolVar(&deepScan, "deep", false, "Include dormant node_modules and developer project artifacts")
	cleanCmd.Flags().StringVarP(&scanPath, "path", "p", "", "Custom project directory to include when using --deep")

	scanCmd.AddCommand(scanJunkCmd)
	scanCmd.AddCommand(scanDevCmd)
	scanCmd.AddCommand(scanBigFilesCmd)
	scanCmd.AddCommand(scanDuplicatesCmd)
	scanCmd.AddCommand(scanAllCmd)

	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(cleanCmd)

	if err := rootCmd.ExecuteContext(ctx); err != nil {
		os.Exit(1)
	}
}

type cleanCategory struct {
	Name       string
	Count      int64
	Size       int64
	Candidates []deleter.DeleteCandidate
}

func runClean(ctx context.Context, cmd *cobra.Command) error {
	del, err := deleter.New()
	if err != nil {
		return fmt.Errorf("failed to initialize deleter: %w", err)
	}

	fmt.Printf("🔍 Scanning for safe-to-delete candidates older than %d days...\n", thresholdDays)
	junkScanner := scanner.NewJunkScanner(nil, thresholdDays)
	res, err := junkScanner.Scan(ctx)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	var categories []cleanCategory

	// Add junk categories
	for _, cat := range res.Categories {
		if cat.ListOnly || cat.CandidateCount == 0 {
			continue
		}
		var cands []deleter.DeleteCandidate
		for _, cand := range res.Candidates {
			if !cand.ListOnly && cand.Category == cat.Name {
				cands = append(cands, deleter.DeleteCandidate{
					Path:     cand.Path,
					Size:     cand.Size,
					Category: cand.Category,
				})
			}
		}
		categories = append(categories, cleanCategory{
			Name:       cat.Name,
			Count:      cat.CandidateCount,
			Size:       cat.CandidateSize,
			Candidates: cands,
		})
	}

	// Deep Scan: include developer build artifacts & dormant node_modules
	if deepScan {
		var roots []string
		if scanPath != "" {
			roots = []string{scanPath}
		}
		devScanner := scanner.NewDevScanner(roots, thresholdDays)
		fmt.Printf("🔍 Performing deep scan on developer workspaces: %s...\n", strings.Join(devScanner.SearchRoots, ", "))
		devRes, err := devScanner.Scan(ctx)
		if err == nil && devRes.CandidateCount > 0 {
			var devCands []deleter.DeleteCandidate
			for _, art := range devRes.Artifacts {
				if art.SafeToDelete {
					devCands = append(devCands, deleter.DeleteCandidate{
						Path:     art.Path,
						Size:     art.Size,
						Category: fmt.Sprintf("Dormant %s (%s)", art.ArtifactType, art.ProjectName),
					})
				}
			}
			categories = append(categories, cleanCategory{
				Name:       fmt.Sprintf("Dormant Developer Artifacts (%d projects)", devRes.CandidateCount),
				Count:      devRes.CandidateCount,
				Size:       devRes.CandidateSize,
				Candidates: devCands,
			})
		}
	}

	if len(categories) == 0 {
		fmt.Println("✨ No safe-to-delete candidates found. Your system is clean!")
		return nil
	}

	var totalCount int64
	var totalSize int64
	for _, c := range categories {
		totalCount += c.Count
		totalSize += c.Size
	}

	// 1. Dry Run Mode
	if dryRun {
		fmt.Println()
		header := lipgloss.NewStyle().
			Bold(true).
			Foreground(report.PureWhite).
			Background(report.AmberWarn).
			Padding(0, 2).
			Render("🛡️  maccleaner clean - DRY-RUN SIMULATION")
		fmt.Println(header)
		fmt.Println()

		for i, cat := range categories {
			fmt.Printf(" [%d] %-42s: %s (%s)\n",
				i+1,
				lipgloss.NewStyle().Bold(true).Render(cat.Name),
				lipgloss.NewStyle().Foreground(report.AccentCyan).Render(fmt.Sprintf("%d items", cat.Count)),
				lipgloss.NewStyle().Foreground(report.GreenAccent).Bold(true).Render(report.FormatBytes(cat.Size)),
			)
		}
		fmt.Println("\n" + strings.Repeat("─", 78))
		fmt.Printf("  • Total Safe Candidates: %s\n",
			lipgloss.NewStyle().Foreground(report.GreenAccent).Bold(true).Render(
				fmt.Sprintf("%d items (%s)", totalCount, report.FormatBytes(totalSize)),
			),
		)

		// Check candidates against deny list
		var allCandidates []deleter.DeleteCandidate
		for _, cat := range categories {
			allCandidates = append(allCandidates, cat.Candidates...)
		}
		delRes, err := del.DeleteBatch(allCandidates, true)
		if err != nil {
			return err
		}

		if len(delRes.Errors) > 0 {
			fmt.Printf("  • Protected paths skipped by Deny-List: %d\n", len(delRes.Errors))
		}
		fmt.Println(strings.Repeat("─", 78))
		fmt.Println(lipgloss.NewStyle().Foreground(report.AmberWarn).Bold(true).Render("🛡️  [DRY-RUN COMPLETE] No files were moved or deleted."))
		fmt.Println("👉  To delete interactively:       maccleaner clean")
		fmt.Println("👉  To delete all without prompt:  maccleaner clean --yes")
		if !deepScan {
			fmt.Println(lipgloss.NewStyle().Foreground(report.MutedGray).Render("💡  Run with '--deep' to also scan for dormant node_modules and build artifacts!"))
		}
		fmt.Println()
		return nil
	}

	// 2. Auto-Confirm Mode (--yes)
	if autoConfirm {
		var allCandidates []deleter.DeleteCandidate
		for _, cat := range categories {
			allCandidates = append(allCandidates, cat.Candidates...)
		}

		fmt.Printf("\n🚀 Moving %d items (%s) to ~/.Trash...\n", totalCount, report.FormatBytes(totalSize))
		delRes, err := del.DeleteBatch(allCandidates, false)
		if err != nil {
			return fmt.Errorf("deletion failed: %w", err)
		}

		printCleanSummary(delRes, del.LogFile)
		return nil
	}

	// 3. Interactive Bubble Tea TUI
	var uiItems []ui.Item
	for _, cat := range categories {
		uiItems = append(uiItems, ui.Item{
			Name:       cat.Name,
			Count:      cat.Count,
			Size:       cat.Size,
			Selected:   true,
			Candidates: cat.Candidates,
		})
	}

	p := tea.NewProgram(ui.NewModel(uiItems, del))
	if _, err := p.Run(); err != nil {
		return fmt.Errorf("UI error: %w", err)
	}
	return nil
}

func printCleanSummary(delRes *deleter.DeleteResult, logPath string) {
	fmt.Println("\n" + strings.Repeat("─", 78))
	header := lipgloss.NewStyle().Bold(true).Foreground(report.GreenAccent).Render("✨ Cleanup Summary:")
	fmt.Println(header)
	fmt.Printf("  • Safely Moved to Trash: %s\n",
		lipgloss.NewStyle().Bold(true).Foreground(report.GreenAccent).Render(
			fmt.Sprintf("%d items (%s)", delRes.DeletedCount, report.FormatBytes(delRes.DeletedSize)),
		),
	)
	if delRes.SkippedCount > 0 {
		fmt.Printf("  • Skipped / Inaccessible: %d items (%s)\n", delRes.SkippedCount, report.FormatBytes(delRes.SkippedSize))
	}
	if delRes.PermissionDeniedCount > 0 {
		fmt.Printf("  • Needs elevation (skipped, no password prompts): %d items (%s)\n",
			delRes.PermissionDeniedCount, report.FormatBytes(delRes.PermissionDeniedSize))
		fmt.Println(lipgloss.NewStyle().Foreground(report.AmberWarn).Render(
			"    Hint: re-run with sudo to include them, or leave them to keep protected files untouched."))
	}
	for _, e := range delRes.Errors {
		fmt.Printf("    • %s\n", lipgloss.NewStyle().Foreground(report.MutedGray).Render(e))
	}
	if delRes.TruncatedErrors {
		fmt.Printf("    • … and more (counts above are exact; showing first %d details)\n", len(delRes.Errors))
	}
	fmt.Printf("  • Audit Log:              %s\n", lipgloss.NewStyle().Foreground(report.AccentCyan).Render(logPath))
	fmt.Println(strings.Repeat("─", 78))
	fmt.Println(lipgloss.NewStyle().Foreground(report.GreenAccent).Render("✅ Done! You can empty your Trash when you're ready."))
	fmt.Println()
}
