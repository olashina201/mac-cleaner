package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"maccleaner/internal/deleter"
	"maccleaner/internal/report"
	"maccleaner/internal/scanner"
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
		fmt.Println("\n=========================================================================================")
		fmt.Println("                       maccleaner clean - DRY-RUN SIMULATION")
		fmt.Println("=========================================================================================")
		for i, cat := range categories {
			fmt.Printf(" [%d] %-42s: %d items (%s)\n", i+1, cat.Name, cat.Count, report.FormatBytes(cat.Size))
		}
		fmt.Println("-----------------------------------------------------------------------------------------")
		fmt.Printf("  • Total Safe Candidates: %d items (%s)\n", totalCount, report.FormatBytes(totalSize))

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
		fmt.Println("-----------------------------------------------------------------------------------------")
		fmt.Println("🛡️  [DRY-RUN COMPLETE] No files were moved or deleted.")
		fmt.Println("👉  To delete interactively:       maccleaner clean")
		fmt.Println("👉  To delete all without prompt:  maccleaner clean --yes")
		if !deepScan {
			fmt.Println("💡  Run with '--deep' to also scan for dormant node_modules and build artifacts!")
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

	// 3. Interactive Category Selection
	fmt.Println("\n=========================================================================================")
	fmt.Println("                          maccleaner clean - Selection Menu")
	fmt.Println("=========================================================================================")
	for i, cat := range categories {
		fmt.Printf("  [%d] %-42s %d items (%s)\n", i+1, cat.Name, cat.Count, report.FormatBytes(cat.Size))
	}
	fmt.Println("-----------------------------------------------------------------------------------------")
	fmt.Printf("  Total available to clean: %d items (%s)\n\n", totalCount, report.FormatBytes(totalSize))

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Select categories to clean (e.g. '1,2', 'a' for all, or 'q' to quit) [a]: ")
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)

	if strings.ToLower(input) == "q" {
		fmt.Println("Aborted. No files were touched.")
		return nil
	}

	var selectedCategories []cleanCategory
	if input == "" || strings.ToLower(input) == "a" || strings.ToLower(input) == "all" {
		selectedCategories = categories
	} else {
		indices := strings.Split(input, ",")
		for _, s := range indices {
			idx, err := strconv.Atoi(strings.TrimSpace(s))
			if err != nil || idx < 1 || idx > len(categories) {
				fmt.Printf("Invalid category index: %q. Operation cancelled.\n", s)
				return nil
			}
			selectedCategories = append(selectedCategories, categories[idx-1])
		}
	}

	var selectedCandidates []deleter.DeleteCandidate
	var selectedSize int64
	for _, cat := range selectedCategories {
		selectedCandidates = append(selectedCandidates, cat.Candidates...)
		selectedSize += cat.Size
	}

	fmt.Printf("\nYou have selected %d categories (%d items, %s).\n",
		len(selectedCategories), len(selectedCandidates), report.FormatBytes(selectedSize))
	fmt.Printf("These items will be moved safely to ~/.Trash (recoverable via Finder).\n")
	fmt.Print("Are you sure you want to proceed? [y/N]: ")

	confirm, _ := reader.ReadString('\n')
	confirm = strings.TrimSpace(strings.ToLower(confirm))

	if confirm != "y" && confirm != "yes" {
		fmt.Println("Aborted. No files were modified.")
		return nil
	}

	fmt.Println("\n🚀 Moving selected items to ~/.Trash...")
	delRes, err := del.DeleteBatch(selectedCandidates, false)
	if err != nil {
		return fmt.Errorf("deletion failed: %w", err)
	}

	printCleanSummary(delRes, del.LogFile)
	return nil
}

func printCleanSummary(delRes *deleter.DeleteResult, logPath string) {
	fmt.Println("\n-----------------------------------------------------------------------------------------")
	fmt.Println("Cleanup Summary:")
	fmt.Printf("  • Safely Moved to Trash: %d items (%s)\n", delRes.DeletedCount, report.FormatBytes(delRes.DeletedSize))
	if delRes.SkippedCount > 0 {
		fmt.Printf("  • Skipped / Inaccessible: %d items (%s)\n", delRes.SkippedCount, report.FormatBytes(delRes.SkippedSize))
	}
	fmt.Printf("  • Audit Log:              %s\n", logPath)
	fmt.Println("-----------------------------------------------------------------------------------------")
	fmt.Println("✅ Done! You can empty your Trash when you're ready, or restore items with 'Put Back'.")
}
