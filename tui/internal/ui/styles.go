/*
Package styles defines the Gordian visual identity.

Theme: OLED Black + Cyberpunk/Hacker aesthetic
Primary: Neon Cyan   │ Status OK: Matrix Green   │ Danger: Blood Red
*/
package ui

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// ── OLED Cyberpunk Palette ──────────────────────────────────────────

var (
	ColorBg          = lipgloss.Color("#000000") // OLED Black
	ColorNeonCyan    = lipgloss.Color("#00FFFF") // Primary / Borders
	ColorNeonBlue    = lipgloss.Color("#0099FF") // Secondary accent
	ColorMatrixGreen = lipgloss.Color("#00FF41") // Status OK
	ColorBloodRed    = lipgloss.Color("#FF0033") // Vulnerabilities / Danger
	ColorAmber       = lipgloss.Color("#FFBF00") // Warnings
	ColorGhost       = lipgloss.Color("#777777") // Brightened from #333333 for readability
	ColorDimCyan     = lipgloss.Color("#00BBBB") // Brightened from #007777 for readability
	ColorWhite       = lipgloss.Color("#FFFFFF") // Brightened text
	ColorDimWhite    = lipgloss.Color("#BBBBBB") // Brightened from #888888 for readability
	ColorPurple      = lipgloss.Color("#CC55FF") // Brightened from #AA00FF for readability
	ColorHotPink     = lipgloss.Color("#FF3388") // Brightened from #FF0066
)

// ── Base Styles ─────────────────────────────────────────────────────

var (
	BaseStyle = lipgloss.NewStyle().
			Background(ColorBg).
			Foreground(ColorWhite)

	RootStyle = lipgloss.NewStyle().
			Background(ColorBg)

	TitleStyle = lipgloss.NewStyle().
			Foreground(ColorNeonCyan).
			Bold(true).
			Background(ColorBg)

	SubtitleStyle = lipgloss.NewStyle().
			Foreground(ColorDimCyan).
			Background(ColorBg)

	DimStyle = lipgloss.NewStyle().
			Foreground(ColorGhost).
			Background(ColorBg)

	HighlightStyle = lipgloss.NewStyle().
			Foreground(ColorNeonCyan).
			Bold(true).
			Background(ColorBg)
)

// ── Panel / Box Styles ──────────────────────────────────────────────

var (
	PanelBorder = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(ColorNeonCyan).
			Background(ColorBg).
			Padding(0, 1)

	PanelBorderActive = lipgloss.NewStyle().
				Border(lipgloss.DoubleBorder()).
				BorderForeground(ColorNeonCyan).
				Background(ColorBg).
				Padding(0, 1)

	PanelBorderDanger = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(ColorBloodRed).
				Background(ColorBg).
				Padding(0, 1)

	PanelHeader = lipgloss.NewStyle().
			Foreground(ColorNeonCyan).
			Bold(true).
			Background(ColorBg).
			Padding(0, 1)
)

// ── Status Indicators ───────────────────────────────────────────────

var (
	StatusOK = lipgloss.NewStyle().
			Foreground(ColorMatrixGreen).
			Bold(true)

	StatusWarning = lipgloss.NewStyle().
			Foreground(ColorAmber).
			Bold(true)

	StatusError = lipgloss.NewStyle().
			Foreground(ColorBloodRed).
			Bold(true)

	StatusRunning = lipgloss.NewStyle().
			Foreground(ColorNeonCyan).
			Bold(true)
)

// ── Tool Styles ─────────────────────────────────────────────────────

var (
	ToolActiveStyle = lipgloss.NewStyle().
			Foreground(ColorMatrixGreen).
			Bold(true).
			Background(ColorBg)

	ToolInactiveStyle = lipgloss.NewStyle().
				Foreground(ColorDimWhite).
				Background(ColorBg)

	ToolSelectedStyle = lipgloss.NewStyle().
				Foreground(ColorNeonCyan).
				Bold(true).
				Background(lipgloss.Color("#001a1a"))

	FindingStyle = lipgloss.NewStyle().
			Foreground(ColorBloodRed).
			Bold(true).
			Background(ColorBg)
)

// ── Log Styles ──────────────────────────────────────────────────────

var (
	LogTimestamp = lipgloss.NewStyle().
			Foreground(ColorDimWhite)

	LogInfo = lipgloss.NewStyle().
		Foreground(ColorMatrixGreen)

	LogWarning = lipgloss.NewStyle().
			Foreground(ColorAmber)

	LogError = lipgloss.NewStyle().
			Foreground(ColorBloodRed).
			Bold(true)

	LogTool = lipgloss.NewStyle().
		Foreground(ColorPurple)

	LogDijkstra = lipgloss.NewStyle().
			Foreground(ColorNeonCyan).
			Bold(true)
)

// ── Key Binding Display ─────────────────────────────────────────────

var (
	KeyStyle = lipgloss.NewStyle().
			Foreground(ColorNeonCyan).
			Bold(true).
			Background(lipgloss.Color("#001a1a")).
			Padding(0, 1)

	KeyDescStyle = lipgloss.NewStyle().
			Foreground(ColorDimWhite).
			Background(ColorBg)
)

// ── Boot Animation ──────────────────────────────────────────────────

var (
	BootArtStyle = lipgloss.NewStyle().
			Foreground(ColorNeonCyan).
			Bold(true).
			Background(ColorBg)

	BootProgressBar = lipgloss.NewStyle().
			Foreground(ColorMatrixGreen).
			Background(ColorBg)

	BootModuleStyle = lipgloss.NewStyle().
			Foreground(ColorDimCyan).
			Background(ColorBg)

	BootPercentStyle = lipgloss.NewStyle().
			Foreground(ColorNeonCyan).
			Bold(true).
			Background(ColorBg)
)

// ── Glitch Effect ───────────────────────────────────────────────────

var (
	GlitchStyle = lipgloss.NewStyle().
			Foreground(ColorBloodRed).
			Bold(true).
			Blink(true).
			Background(ColorBg)

	AlertBorder = lipgloss.NewStyle().
			Border(lipgloss.ThickBorder()).
			BorderForeground(ColorBloodRed).
			Foreground(ColorBloodRed).
			Bold(true).
			Background(ColorBg).
			Padding(0, 1)
)

// ── Extra panel header variant ───────────────────────────────────────

var (
	PanelHeaderDanger = lipgloss.NewStyle().
				Foreground(ColorBloodRed).
				Bold(true).
				Background(ColorBg).
				Padding(0, 1)
)

// ── Category colors ──────────────────────────────────────────────────

var (
	CatScan    = lipgloss.NewStyle().Foreground(ColorNeonCyan).Background(ColorBg)
	CatRecon   = lipgloss.NewStyle().Foreground(ColorAmber).Background(ColorBg)
	CatExploit = lipgloss.NewStyle().Foreground(ColorBloodRed).Background(ColorBg)
	CatUtil    = lipgloss.NewStyle().Foreground(ColorPurple).Background(ColorBg)
)

// ── Error Overlay ───────────────────────────────────────────────────

var (
	ErrorOverlay = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(ColorBloodRed).
			Background(lipgloss.Color("#0a0000")).
			Foreground(ColorBloodRed).
			Bold(true).
			Padding(0, 2)

	ErrorDimText = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#993333")).
			Background(lipgloss.Color("#0a0000"))
)

// ── Scan Pulse Indicator ────────────────────────────────────────────

var (
	ScanPulseActive = lipgloss.NewStyle().
			Foreground(ColorNeonCyan).
			Bold(true).
			Blink(true).
			Background(ColorBg)

	ScanPulseIdle = lipgloss.NewStyle().
			Foreground(ColorGhost).
			Background(ColorBg)
)
// ── Helpers ─────────────────────────────────────────────────────────

func truncateLines(s string, maxLines int) string {
	lines := strings.Split(s, "\n")
	if len(lines) > maxLines {
		return strings.Join(lines[:maxLines], "\n")
	}
	return s
}
