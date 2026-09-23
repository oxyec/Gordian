/*
Toolbox panel — lists offensive tools, supports on-demand launch,
chaining preview, and parallel/sequential toggle.
*/
package ui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"gordian-tui/internal/state"
)

// categoryStyle returns color for a tool category label.
func categoryStyle(cat string) lipgloss.Style {
	switch cat {
	case "scan":
		return CatScan
	case "recon":
		return CatRecon
	case "exploit":
		return CatExploit
	default:
		return CatUtil
	}
}

// RenderToolbox renders the tool management sidebar.
func RenderToolbox(tools []state.Tool, selectedIdx int, chainMode bool, parallelMode bool, width, height int) string {
	var b strings.Builder

	w := width - 4
	h := height - 2
	if w < 1 {
		w = 1
	}
	if h < 1 {
		h = 1
	}

	// Count active / running
	activeCount, runningCount := 0, 0
	for _, t := range tools {
		if t.Running {
			runningCount++
		} else if t.Enabled {
			activeCount++
		}
	}

	// Header with tool counts
	headerText := "⚔ TOOLBOX"
	countBadge := ""
	if runningCount > 0 {
		countBadge = "  " + StatusRunning.Render(fmt.Sprintf("▶%d", runningCount)) +
			DimStyle.Render(fmt.Sprintf(" /%d", len(tools)))
	} else {
		countBadge = "  " + StatusOK.Render(fmt.Sprintf("◈%d", activeCount)) +
			DimStyle.Render(fmt.Sprintf(" /%d", len(tools)))
	}
	b.WriteString(PanelHeader.Render(headerText + countBadge))
	b.WriteString("\n")

	// Tool list
	for i, tool := range tools {
		cursor := "  "
		if i == selectedIdx {
			cursor = HighlightStyle.Render("▸ ")
		}

		// Status icon
		var statusIcon string
		var nameStyled string
		if tool.Running {
			statusIcon = StatusRunning.Render("▶")
			nameStyled = lipgloss.NewStyle().Foreground(ColorNeonCyan).Bold(true).Background(ColorBg).Render(tool.Name)
		} else if tool.Enabled {
			statusIcon = StatusOK.Render("◈")
			nameStyled = ToolActiveStyle.Render(tool.Name)
		} else {
			statusIcon = lipgloss.NewStyle().Foreground(ColorGhost).Background(ColorBg).Render("◦")
			nameStyled = ToolInactiveStyle.Render(tool.Name)
		}

		// Category badge
		catBadge := categoryStyle(tool.Category).Render(fmt.Sprintf("%-7s", tool.Category))

		// Build line with proper padding for alignment
		namePadded := fmt.Sprintf("%-12s", nameStyled)
		line := fmt.Sprintf("%s%s %s %s", cursor, statusIcon, namePadded, catBadge)

		if i == selectedIdx {
			line = ToolSelectedStyle.
				Width(w).
				Render(line)
		}

		b.WriteString(line + "\n")
	}

	// ── Tool Description (when selected) ──
	if selectedIdx >= 0 && selectedIdx < len(tools) {
		desc := tools[selectedIdx].Description
		if desc != "" {
			b.WriteString("\n")
			// Wrap description to fit panel width
			if len(desc) > w-4 && w > 8 {
				desc = desc[:w-5] + "…"
			}
			b.WriteString(DimStyle.Render(fmt.Sprintf("  %s %s",
				tools[selectedIdx].Icon,
				desc)))
			b.WriteString("\n")
		}
	}

	// ── Pipeline Mode ──
	b.WriteString("\n")

	// Dynamic-width separator
	sepWidth := w - 4
	dashCount := sepWidth - 13
	if dashCount < 3 {
		dashCount = 3
	}
	b.WriteString(SubtitleStyle.Render(fmt.Sprintf("  ─ Pipeline %s", strings.Repeat("─", dashCount))))
	b.WriteString("\n")

	chainLabel := DimStyle.Render("OFF")
	if chainMode {
		chainLabel = StatusOK.Render("ON ")
	}

	var modeStr string
	if parallelMode {
		modeStr = StatusRunning.Render("⇉ Parallel  ")
	} else {
		modeStr = StatusWarning.Render("→ Sequential")
	}
	b.WriteString(fmt.Sprintf("  Chain: %s    Mode: %s\n", chainLabel, modeStr))

	// Chain flow preview
	if chainMode {
		enabled := []string{}
		for _, t := range tools {
			if t.Enabled {
				enabled = append(enabled, t.Name)
			}
		}
		if len(enabled) > 0 {
			b.WriteString("\n")
			sep := SubtitleStyle.Render(" ▸ ")
			flow := ToolActiveStyle.Render(strings.Join(enabled, sep))
			// Truncate if too wide
			innerW := w - 4
			if lipgloss.Width(flow) > innerW && innerW > 8 {
				maxItems := 3
				if len(enabled) < maxItems {
					maxItems = len(enabled)
				}
				flow = ToolActiveStyle.Render(strings.Join(enabled[:maxItems], sep)) +
					DimStyle.Render("…")
			}
			b.WriteString("  " + flow + "\n")
		}
	}

	// ── Key hints ──
	b.WriteString("\n")
	b.WriteString(fmt.Sprintf("  %s select  %s toggle  %s chain  %s mode\n",
		KeyStyle.Render("↑↓"),
		KeyStyle.Render("⎵"),
		KeyStyle.Render("C"),
		KeyStyle.Render("p"),
	))

	content := truncateLines(b.String(), h)
	return PanelBorder.Width(w).Height(h).Render(content)
}
