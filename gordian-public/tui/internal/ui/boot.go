/*
Boot animation — renders the Gordian sword ASCII art line-by-line
with a progress bar and system module loading sequence at ~60 FPS.
Auto-advances after a short delay; Enter/Space to skip.
*/
package ui

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// ── Sword ASCII Art (from main.py) ──────────────────────────────────

var swordArt = []string{
	``,
	`         /\`,
	`        /  \`,
	`       |    |`,
	`       |    |`,
	`     __|____|__        ____               _ _`,
	`    [==========]      / ___| ___  _ __ __| (_) __ _ _ __`,
	`        |  |         | |  _ / _ \| '__/ _` + "`" + ` | |/ _` + "`" + ` | '_ \`,
	`     o--|--|--o      | |_| | (_) | | | (_| | | (_| | | | |`,
	`    / \ |  | / \      \____|\___/|_|  \__,_|_|\__,_|_| |_|`,
	`   o---o|--|o---o`,
	`  / \ / |  | \ / \`,
	` o---o  |  |  o---o`,
	`  \ / \ |  | / \ /`,
	`   o---o|--|o---o`,
	`    \ / |  | \ /`,
	`     o--|--|--o`,
	`        |  |`,
	`        \  /`,
	`         \/`,
}

var bootModules = []string{
	"core.bootloader",
	"topology.parser",
	"cve.connectors",
	"transform.graph_engine",
	"policy.scope_guards",
	"remediation.simulator",
	"offensive.command_planner",
	"api.fastapi_bus",
	"ws.broadcast_layer",
	"storage.backend_init",
	"dijkstra.pathfinder",
	"tui.render_engine",
	"tui.event_dispatcher",
	"system.ready",
}

// ── Boot Model ──────────────────────────────────────────────────────

type BootModel struct {
	artIndex     int
	moduleIndex  int
	width        int
	height       int
	done         bool
	startTime    time.Time
	allLoaded    bool      // all modules finished loading
	loadedAt     time.Time // when loading completed
	autoAdvDelay time.Duration
}

type bootTickMsg time.Time

func NewBootModel() BootModel {
	return BootModel{
		startTime:    time.Now(),
		width:        80,
		height:       24,
		autoAdvDelay: 1500 * time.Millisecond,
	}
}

func bootTick() tea.Cmd {
	return tea.Tick(time.Millisecond*100, func(t time.Time) tea.Msg {
		return bootTickMsg(t)
	})
}

func (m BootModel) Init() tea.Cmd {
	return bootTick()
}

func (m BootModel) Update(msg tea.Msg) (BootModel, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case bootTickMsg:
		_ = msg
		if m.artIndex < len(swordArt) {
			m.artIndex++
			return m, bootTick()
		}
		if m.moduleIndex < len(bootModules) {
			m.moduleIndex++
			if m.moduleIndex >= len(bootModules) && !m.allLoaded {
				m.allLoaded = true
				m.loadedAt = time.Now()
			}
			return m, bootTick()
		}
		// Auto-advance after delay
		if m.allLoaded && time.Since(m.loadedAt) >= m.autoAdvDelay {
			m.done = true
			return m, nil
		}
		return m, bootTick()

	case tea.KeyMsg:
		if msg.String() == "enter" || msg.String() == " " {
			m.done = true
			return m, nil
		}
	}
	return m, nil
}

func (m BootModel) IsDone() bool {
	return m.done
}

func (m BootModel) View() string {
	var b strings.Builder

	// ── Sword Art ──
	artLines := swordArt
	if m.artIndex < len(artLines) {
		artLines = artLines[:m.artIndex]
	}

	// Find the widest art line for centering
	maxArtWidth := 0
	for _, line := range artLines {
		if len(line) > maxArtWidth {
			maxArtWidth = len(line)
		}
	}

	for _, line := range artLines {
		b.WriteString(BootArtStyle.Render(line))
		b.WriteString("\n")
	}

	if m.artIndex >= len(swordArt) {
		b.WriteString("\n")

		// ── Module loading lines ──
		total := len(bootModules)
		shown := m.moduleIndex
		if shown > total {
			shown = total
		}

		for i := 0; i < shown; i++ {
			pct := (i + 1) * 100 / total
			barFill := pct / 5
			if barFill > 20 {
				barFill = 20
			}
			bar := strings.Repeat("█", barFill) + strings.Repeat("░", 20-barFill)

			var pctStyle lipgloss.Style
			if pct < 40 {
				pctStyle = StatusWarning
			} else if pct < 85 {
				pctStyle = StatusOK
			} else {
				pctStyle = BootPercentStyle
			}

			line := fmt.Sprintf(
				"  %s %s %s",
				pctStyle.Render(fmt.Sprintf("[%3d%%]", pct)),
				BootProgressBar.Render("["+bar+"]"),
				BootModuleStyle.Render(bootModules[i]),
			)
			b.WriteString(line)
			b.WriteString("\n")
		}

		// ── Server info banner ──
		if shown >= total {
			b.WriteString("\n")

			// Blinking cursor effect on the prompt
			promptText := "  Press [ENTER] to enter the command center"
			if m.allLoaded && time.Since(m.loadedAt).Milliseconds()%800 < 400 {
				promptText = "  Press [ENTER] to enter the command center  ▌"
			}

			banner := lipgloss.NewStyle().
				Border(lipgloss.DoubleBorder()).
				BorderForeground(ColorNeonCyan).
				Foreground(ColorNeonCyan).
				Bold(true).
				Padding(0, 2).
				Render(
					"  ⚔  GORDIAN COMMAND CENTER  ⚔\n" +
						"  ─── Attack Path Intelligence ───\n\n" +
						promptText,
				)
			b.WriteString(banner)
			b.WriteString("\n")
		}
	}

	content := b.String()

	// Center the content vertically and horizontally
	contentLines := strings.Split(content, "\n")
	contentHeight := len(contentLines)
	topPad := (m.height - contentHeight) / 2
	if topPad < 0 {
		topPad = 0
	}

	// Find max content width for horizontal centering
	maxContentWidth := 0
	for _, line := range contentLines {
		w := lipgloss.Width(line)
		if w > maxContentWidth {
			maxContentWidth = w
		}
	}
	leftPad := (m.width - maxContentWidth) / 2
	if leftPad < 0 {
		leftPad = 0
	}

	// Build centered output
	var out strings.Builder
	padLine := lipgloss.NewStyle().Background(ColorBg).Width(m.width).Render("")
	for i := 0; i < topPad; i++ {
		out.WriteString(padLine)
		out.WriteString("\n")
	}
	prefix := strings.Repeat(" ", leftPad)
	for _, line := range contentLines {
		out.WriteString(prefix)
		out.WriteString(line)
		out.WriteString("\n")
	}

	return out.String()
}
