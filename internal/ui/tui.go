package ui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"maccleaner/internal/deleter"
	"maccleaner/internal/report"
)

// UI Color Palette
var (
	PrimaryColor   = lipgloss.Color("#7D56F4") // Electric Purple
	SecondaryColor = lipgloss.Color("#04D9FF") // Cyan
	SuccessColor   = lipgloss.Color("#00F5D4") // Emerald Green
	WarningColor   = lipgloss.Color("#FFBE0B") // Amber
	DangerColor    = lipgloss.Color("#FF007F") // Coral/Pink
	MutedColor     = lipgloss.Color("#6C7A89") // Slate Muted
	BgHighlight    = lipgloss.Color("#2A2B3D") // Cursor highlight bg
	WhiteColor     = lipgloss.Color("#FFFFFF")

	// Styles
	TitleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(WhiteColor).
			Background(PrimaryColor).
			Padding(0, 2)

	SubTitleStyle = lipgloss.NewStyle().
			Foreground(SecondaryColor).
			Bold(true)

	BorderBox = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(PrimaryColor).
			Padding(1, 2)

	SuccessBadge = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#000000")).
			Background(SuccessColor).
			Padding(0, 1)

	WarningBadge = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#000000")).
			Background(WarningColor).
			Padding(0, 1)

	CursorStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(SecondaryColor)

	SelectedItemStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(WhiteColor)

	UnselectedItemStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#A0AEC0"))

	KeyHintStyle = lipgloss.NewStyle().
			Foreground(SecondaryColor).
			Bold(true)
	DescHintStyle = lipgloss.NewStyle().
			Foreground(MutedColor)
)

// Item represents a cleanable category or project in the TUI.
type Item struct {
	Name       string
	Count      int64
	Size       int64
	Selected   bool
	Candidates []deleter.DeleteCandidate
}

type state int

const (
	stateSelecting state = iota
	stateConfirming
	stateDone
	stateCancelled
)

// Model is the bubbletea UI model for interactive cleaning.
type Model struct {
	Items     []Item
	Cursor    int
	State     state
	Confirmed bool
	Del       *deleter.Deleter
	Result    *deleter.DeleteResult
	Err       error
}

// NewModel creates an interactive TUI model.
func NewModel(items []Item, del *deleter.Deleter) Model {
	// Select all by default
	for i := range items {
		items[i].Selected = true
	}
	return Model{
		Items:  items,
		Cursor: 0,
		State:  stateSelecting,
		Del:    del,
	}
}

func (m Model) Init() tea.Cmd {
	return nil
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			if m.State == stateConfirming {
				m.State = stateSelecting
				return m, nil
			}
			m.State = stateCancelled
			return m, tea.Quit

		case "up", "k":
			if m.State == stateSelecting && m.Cursor > 0 {
				m.Cursor--
			}
		case "down", "j":
			if m.State == stateSelecting && m.Cursor < len(m.Items)-1 {
				m.Cursor++
			}

		case " ":
			if m.State == stateSelecting && len(m.Items) > 0 {
				m.Items[m.Cursor].Selected = !m.Items[m.Cursor].Selected
			}

		case "a":
			if m.State == stateSelecting {
				allSelected := true
				for _, it := range m.Items {
					if !it.Selected {
						allSelected = false
						break
					}
				}
				for i := range m.Items {
					m.Items[i].Selected = !allSelected
				}
			}

		case "enter":
			if m.State == stateSelecting {
				if m.SelectedSize() > 0 {
					m.State = stateConfirming
				}
				return m, nil
			} else if m.State == stateConfirming {
				m.Confirmed = true
				m.State = stateDone
				// Perform deletion
				var allCands []deleter.DeleteCandidate
				for _, it := range m.Items {
					if it.Selected {
						allCands = append(allCands, it.Candidates...)
					}
				}
				res, err := m.Del.DeleteBatch(allCands, false)
				m.Result = res
				m.Err = err
				return m, tea.Quit
			}

		case "y", "Y":
			if m.State == stateConfirming {
				m.Confirmed = true
				m.State = stateDone
				var allCands []deleter.DeleteCandidate
				for _, it := range m.Items {
					if it.Selected {
						allCands = append(allCands, it.Candidates...)
					}
				}
				res, err := m.Del.DeleteBatch(allCands, false)
				m.Result = res
				m.Err = err
				return m, tea.Quit
			}

		case "n", "N", "esc":
			if m.State == stateConfirming {
				m.State = stateSelecting
				return m, nil
			}
		}
	}
	return m, nil
}

func (m Model) SelectedCount() int64 {
	var n int64
	for _, it := range m.Items {
		if it.Selected {
			n += it.Count
		}
	}
	return n
}

func (m Model) SelectedSize() int64 {
	var s int64
	for _, it := range m.Items {
		if it.Selected {
			s += it.Size
		}
	}
	return s
}

func (m Model) View() string {
	var sb strings.Builder

	// Header Banner
	header := TitleStyle.Render("🧹 maccleaner - Interactive Disk Cleaner")
	sb.WriteString("\n" + header + "\n\n")

	switch m.State {
	case stateSelecting:
		sb.WriteString(SubTitleStyle.Render("Select categories to clean:") + "\n\n")

		for i, item := range m.Items {
			cursor := "  "
			if m.Cursor == i {
				cursor = CursorStyle.Render("❯ ")
			}

			checked := lipgloss.NewStyle().Foreground(MutedColor).Render("[ ]")
			if item.Selected {
				checked = lipgloss.NewStyle().Foreground(SuccessColor).Bold(true).Render("[✓]")
			}

			name := UnselectedItemStyle.Render(fmt.Sprintf("%-42s", item.Name))
			if item.Selected {
				name = SelectedItemStyle.Render(fmt.Sprintf("%-42s", item.Name))
			}

			stats := lipgloss.NewStyle().Foreground(SuccessColor).Bold(true).Render(
				fmt.Sprintf("%6d items (%s)", item.Count, report.FormatBytes(item.Size)),
			)

			line := fmt.Sprintf("%s%s %s %s", cursor, checked, name, stats)
			if m.Cursor == i {
				line = lipgloss.NewStyle().Background(BgHighlight).Render(line)
			}
			sb.WriteString(line + "\n")
		}

		// Selected Summary Footer
		sb.WriteString("\n" + strings.Repeat("─", 78) + "\n")
		totalStr := lipgloss.NewStyle().Foreground(SuccessColor).Bold(true).Render(
			fmt.Sprintf("%d items (%s)", m.SelectedCount(), report.FormatBytes(m.SelectedSize())),
		)
		sb.WriteString(fmt.Sprintf("Selected: %s\n\n", totalStr))

		// Keybindings Help
		help := fmt.Sprintf("%s %s   %s %s   %s %s   %s %s   %s %s",
			KeyHintStyle.Render("↑/↓"), DescHintStyle.Render("navigate"),
			KeyHintStyle.Render("space"), DescHintStyle.Render("toggle"),
			KeyHintStyle.Render("a"), DescHintStyle.Render("toggle all"),
			KeyHintStyle.Render("enter"), DescHintStyle.Render("clean"),
			KeyHintStyle.Render("q"), DescHintStyle.Render("quit"),
		)
		sb.WriteString(help + "\n")

	case stateConfirming:
		boxContent := fmt.Sprintf(
			"⚠️  %s\n\n"+
				"You are about to move %s to %s.\n\n"+
				"• Safe & Reversible: All items are moved to Trash with macOS 'Put Back' intact.\n"+
				"• Deny-List Checked: System & SIP directories are untouched.\n"+
				"• Audit Log: Recorded in ~/.maccleaner/deletions.log\n\n"+
				"Press %s or %s to proceed, or %s / %s to go back.",
			lipgloss.NewStyle().Bold(true).Foreground(WarningColor).Render("Confirm Safe Deletion"),
			lipgloss.NewStyle().Bold(true).Foreground(SuccessColor).Render(fmt.Sprintf("%d items (%s)", m.SelectedCount(), report.FormatBytes(m.SelectedSize()))),
			lipgloss.NewStyle().Bold(true).Foreground(WhiteColor).Render("~/.Trash"),
			KeyHintStyle.Render("[Enter]"), KeyHintStyle.Render("[y]"),
			KeyHintStyle.Render("[Esc]"), KeyHintStyle.Render("[n]"),
		)
		sb.WriteString(BorderBox.Render(boxContent) + "\n")

	case stateDone:
		if m.Err != nil {
			sb.WriteString(lipgloss.NewStyle().Foreground(DangerColor).Bold(true).Render(
				fmt.Sprintf("❌ Error during cleanup: %v\n", m.Err),
			))
		} else if m.Result != nil {
			resBox := fmt.Sprintf(
				"✨ %s\n\n"+
					"• Safely moved to Trash: %s\n"+
					"• Audit Log:              %s\n\n"+
					"You can empty your Trash when ready or restore any file via Finder.",
				lipgloss.NewStyle().Bold(true).Foreground(SuccessColor).Render("Cleanup Completed Successfully!"),
				lipgloss.NewStyle().Bold(true).Foreground(SuccessColor).Render(fmt.Sprintf("%d items (%s)", m.Result.DeletedCount, report.FormatBytes(m.Result.DeletedSize))),
				lipgloss.NewStyle().Foreground(SecondaryColor).Render(m.Del.LogFile),
			)
			sb.WriteString(BorderBox.Render(resBox) + "\n")
		}

	case stateCancelled:
		sb.WriteString(lipgloss.NewStyle().Foreground(WarningColor).Render("Operation cancelled. No files were modified.\n"))
	}

	return sb.String()
}
