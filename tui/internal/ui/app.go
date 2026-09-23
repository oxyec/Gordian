/*
App — main Bubble Tea model that orchestrates all views:
boot animation → dashboard (map + toolbox + log + config).

Keyboard shortcuts:

	s       start scan
	S       show last report path
	x       cancel running scan
	m       map view
	c       config view
	t       toolbox view
	tab     cycle panels
	ctrl+s  save config profile to disk
	ctrl+l  load config profile from disk
	q/esc   quit
*/
package ui

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"gordian-tui/internal/api"
	"gordian-tui/internal/state"
)

// ── Bubble Tea Messages ─────────────────────────────────────────────

type wsEventMsg struct {
	Event state.LiveEvent
}
type wsConnectedMsg struct{}
type scanStatusMsg state.ScanInfo
type serverInfoMsg struct {
	Version string
	Status  string
	Storage string
	MaxScan int
}
type scanStartedMsg struct{ ScanID string }
type scanCancelledMsg struct{ ScanID string }
type scanErrorMsg struct{ Err error }
type reportSavedMsg struct{ Path string }
type wsReconnectingMsg struct{ Attempt int }
type wsDisconnectedMsg struct{}
type profileSavedMsg struct{ Path string }
type profileLoadedMsg struct{ Path string }
type tickMsg time.Time
type graphDataMsg struct {
	Hosts       []state.HostNode
	Edges       []state.GraphEdge
	EntryPoints []string
	CrownJewels []string
}
type killChainMsg []state.KillChain
type findingsSnapshotMsg []state.Finding

// ── App Model ───────────────────────────────────────────────────────

type AppModel struct {
	// Sub-models
	boot   BootModel
	config ConfigModel

	// State
	state              *state.AppState
	client             *api.Client
	wsClient           *api.WSClient
	wsURL              string
	wsReconnectAttempt int

	// UI state
	phase         string // "boot", "dashboard"
	width, height int
	activePanel   int // 0=dashboard map, 2=config
	err           error
	toasts        *ToastManager

	// Map Navigation State
	mapCursorX int
	mapCursorY int
	mapOffsetX int
	mapOffsetY int
}

func NewAppModel(apiBase, wsURL string) AppModel {
	appState := state.NewAppState(apiBase)
	return AppModel{
		boot:       NewBootModel(),
		config:     NewConfigModel(appState.GetScanConfig()),
		state:      appState,
		client:     api.NewClient(apiBase),
		wsClient:   api.NewWSClient(wsURL),
		wsURL:      wsURL,
		phase:      "boot",
		width:      120,
		height:     40,
		toasts:     NewToastManager(),
		mapCursorX: 70, // Start roughly in the middle
		mapCursorY: 30,
	}
}

func (m AppModel) Init() tea.Cmd {
	return tea.Batch(
		m.boot.Init(),
		m.connectWS(),
		m.fetchServerInfo(),
		tickCmd(),
	)
}

func tickCmd() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

// ── Update ──────────────────────────────────────────────────────────

func (m AppModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		boot, cmd := m.boot.Update(msg)
		m.boot = boot
		return m, cmd

	case tea.KeyMsg:
		return m.handleKey(msg)

	case bootTickMsg:
		if m.phase == "boot" {
			boot, cmd := m.boot.Update(msg)
			m.boot = boot
			if m.boot.IsDone() {
				m.phase = "dashboard"
				return m, tea.Batch(
					m.fetchScanStatus(),
					m.fetchGraph(),
					m.fetchKillChains(),
					m.fetchFindings(),
				)
			}
			return m, cmd
		}

	case tickMsg:
		if m.toasts != nil {
			m.toasts.Update()
		}
		cmds := []tea.Cmd{tickCmd()}
		if m.phase == "dashboard" {
			if m.state.CurrentScan.Status == "running" {
				cmds = append(cmds, m.fetchScanStatus())
			} else {
				// Periodic server status refresh every 5 ticks (~5s)
				if time.Now().Second()%5 == 0 {
					cmds = append(cmds, m.fetchServerInfo())
				}
			}
		}
		return m, tea.Batch(cmds...)

	case wsConnectedMsg:
		m.state.SetWSConnected(true)
		m.state.ClearError()
		m.wsReconnectAttempt = 0
		return m, m.listenWS()

	case wsDisconnectedMsg:
		m.state.SetWSConnected(false)
		m.wsReconnectAttempt++
		// Backoff: 1s, 2s, 4s, 8s, 16s, capped at 30s.
		backoff := time.Duration(1<<uint(min(m.wsReconnectAttempt-1, 5))) * time.Second
		if backoff > 30*time.Second {
			backoff = 30 * time.Second
		}
		// Rebuild the client — the old one used sync.Once and can't be reused.
		m.wsClient = api.NewWSClient(m.wsURL)
		attempt := m.wsReconnectAttempt
		client := m.wsClient
		return m, tea.Batch(
			func() tea.Msg { return wsReconnectingMsg{Attempt: attempt} },
			tea.Tick(backoff, func(time.Time) tea.Msg {
				if err := client.Connect(); err != nil {
					return wsDisconnectedMsg{}
				}
				return wsConnectedMsg{}
			}),
		)

	case wsEventMsg:
		m.state.PushEvent(msg.Event)
		// Trigger glitch on critical findings
		if strings.Contains(msg.Event.Type, "finding") || msg.Event.Level == "ERROR" {
			m.state.TriggerGlitch(2 * time.Second)
		}
		// Live wiring: WS events update state immediately so the operator
		// sees activity without waiting for the next status poll.
		cmd := m.applyLiveEvent(msg.Event)
		if cmd != nil {
			return m, tea.Batch(m.listenWS(), cmd)
		}
		return m, m.listenWS()

	case serverInfoMsg:
		m.state.ServerVersion = msg.Version
		m.state.ServerStatus = msg.Status
		m.state.StorageMode = msg.Storage
		m.state.MaxConcurrent = msg.MaxScan
		return m, nil

	case scanStatusMsg:
		info := state.ScanInfo(msg)
		m.state.SetScanInfo(info)
		return m, nil

	case scanStartedMsg:
		m.state.CurrentScan.ScanID = msg.ScanID
		m.state.CurrentScan.Status = "running"
		if m.toasts != nil {
			m.toasts.Add("scan started: "+msg.ScanID, ToastSuccess, 3*time.Second)
		}
		return m, m.fetchScanStatus()

	case scanErrorMsg:
		m.err = msg.Err
		m.state.SetLastError(msg.Err.Error())
		if m.toasts != nil {
			m.toasts.Add(msg.Err.Error(), ToastError, 5*time.Second)
		}
		return m, nil

	case scanCancelledMsg:
		m.state.CurrentScan.Status = "failed"
		if m.toasts != nil {
			m.toasts.Add("scan cancelled: "+msg.ScanID, ToastInfo, 3*time.Second)
		}
		return m, m.fetchScanStatus()

	case reportSavedMsg:
		if m.toasts != nil {
			m.toasts.Add("report: "+msg.Path, ToastSuccess, 5*time.Second)
		}
		return m, nil

	case profileSavedMsg:
		if m.toasts != nil {
			m.toasts.Add("profile saved: "+msg.Path, ToastSuccess, 3*time.Second)
		}
		return m, nil

	case profileLoadedMsg:
		// Sync the config sub-model with the freshly loaded scan config so
		// the form view re-renders with the new values immediately.
		m.config = NewConfigModel(m.state.GetScanConfig())
		if m.toasts != nil {
			m.toasts.Add("profile loaded: "+msg.Path, ToastSuccess, 3*time.Second)
		}
		return m, nil

	case wsReconnectingMsg:
		if m.toasts != nil {
			m.toasts.Add(fmt.Sprintf("websocket reconnecting (attempt %d)…", msg.Attempt), ToastInfo, 2*time.Second)
		}
		return m, nil

	case graphDataMsg:
		m.state.Hosts = msg.Hosts
		m.state.Edges = msg.Edges
		m.state.EntryPoints = msg.EntryPoints
		m.state.CrownJewels = msg.CrownJewels
		return m, nil

	case findingsSnapshotMsg:
		m.state.ReplaceFindings([]state.Finding(msg))
		return m, nil

	case killChainMsg:
		m.state.KillChains = []state.KillChain(msg)
		return m, nil
	}

	return m, nil
}

func (m AppModel) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := msg.String()

	if m.phase == "dashboard" && m.activePanel == 2 {
		handled, cmd := m.config.HandleKey(msg, m.state)
		if handled {
			return m, cmd
		}
	}

	if m.phase == "dashboard" && key == "esc" && m.activePanel == 2 && !m.config.IsEditing() {
		m.activePanel = 0
		m.state.ActiveView = "dashboard"
		return m, nil
	}

	// Global keys
	switch key {
	case "ctrl+c", "q":
		return m, tea.Quit
	case "esc":
		return m, tea.Quit
	}

	if m.phase == "boot" {
		boot, cmd := m.boot.Update(msg)
		m.boot = boot
		if m.boot.IsDone() {
			m.phase = "dashboard"
			return m, tea.Batch(
				m.fetchScanStatus(),
				m.fetchGraph(),
				m.fetchKillChains(),
			)
		}
		return m, cmd
	}

	// Dashboard keys
	switch key {
	case "s":
		return m, m.startScan()
	case "x":
		if id := m.state.CurrentScan.ScanID; id != "" && m.state.CurrentScan.Status == "running" {
			return m, m.cancelScan(id)
		}
		if m.toasts != nil {
			m.toasts.Add("no running scan to cancel", ToastInfo, 3*time.Second)
		}
		return m, nil
	case "S":
		return m, m.saveReport()
	case "ctrl+s":
		return m, m.saveProfile()
	case "ctrl+l":
		return m, m.loadProfile()
	case "m", "d":
		m.activePanel = 0
		m.state.ActiveView = "dashboard"
		return m, nil
	case "c":
		if m.activePanel == 2 {
			m.activePanel = 0
			m.state.ActiveView = "dashboard"
		} else {
			m.activePanel = 2
			m.state.ActiveView = "config"
		}
		return m, nil
	case "tab", "shift+tab":
		if m.activePanel == 2 {
			m.activePanel = 0
			m.state.ActiveView = "dashboard"
		} else {
			m.activePanel = 2
			m.state.ActiveView = "config"
		}
		return m, nil
	case "up", "k":
		if m.activePanel == 0 {
			m.mapCursorY--
			if m.mapCursorY < 0 {
				m.mapCursorY = 0
			}
		}
	case "down", "j":
		if m.activePanel == 0 {
			m.mapCursorY++
			if m.mapCursorY > 59 { // map is 60 rows
				m.mapCursorY = 59
			}
		}
	case "left", "h":
		if m.activePanel == 0 {
			m.mapCursorX--
			if m.mapCursorX < 0 {
				m.mapCursorX = 0
			}
		}
	case "right", "l":
		if m.activePanel == 0 {
			m.mapCursorX++
			if m.mapCursorX > 139 { // map is 140 cols
				m.mapCursorX = 139
			}
		}
	case "+", "=":
		if m.state.MaxConcurrent < 10 {
			m.state.MaxConcurrent++
		}
	case "-":
		if m.state.MaxConcurrent > 1 {
			m.state.MaxConcurrent--
		}
	case "r":
		return m, tea.Batch(
			m.fetchScanStatus(),
			m.fetchGraph(),
			m.fetchKillChains(),
			m.fetchFindings(),
			m.fetchServerInfo(),
		)
	}

	return m, nil
}

// ── View ────────────────────────────────────────────────────────────

func (m AppModel) View() string {
	var base string

	if m.phase == "boot" {
		base = lipgloss.NewStyle().
			Background(ColorBg).
			Width(m.width).
			Height(m.height).
			Render(m.boot.View())
	} else if m.state.ActiveView == "config" || m.activePanel == 2 {
		base = m.renderConfigView()
	} else {
		base = m.renderDashboard()
	}

	if m.toasts != nil && m.toasts.HasActive() {
		toast := m.toasts.Render(m.width)
		lines := strings.Split(base, "\n")
		if len(lines) > 3 {
			insertIdx := len(lines) - 3
			lines = append(lines[:insertIdx], append([]string{toast}, lines[insertIdx:]...)...)
		} else {
			lines = append(lines, toast)
		}
		base = strings.Join(lines, "\n")
	}

	return base
}

func (m AppModel) renderDashboard() string {
	w, h := m.width, m.height
	ly := NewLayoutEngine(w, h).Calculate()

	headerPanel, _ := m.renderHeader(w)

	overviewPanel := m.renderThreatOverviewPanel(ly.RightWidth, ly.TopRowHeight)
	overviewPanel = lipgloss.NewStyle().Width(ly.RightWidth).Height(ly.TopRowHeight).Background(ColorBg).Render(overviewPanel)

	mapPanel := RenderWorldMap(m.state.GeoMarkers, ly.MapWidth, ly.TopRowHeight, true, m.mapCursorX, m.mapCursorY)
	mapPanel = lipgloss.NewStyle().Width(ly.MapWidth).Height(ly.TopRowHeight).Background(ColorBg).Render(mapPanel)

	topRow := lipgloss.JoinHorizontal(lipgloss.Top, overviewPanel, mapPanel)

	killPanel := RenderKillChains(m.state.KillChains, w, ly.BottomHeight)
	killPanel = lipgloss.NewStyle().Width(w).Height(ly.BottomHeight).Background(ColorBg).Render(killPanel)

	bodyRow := lipgloss.JoinVertical(lipgloss.Left, topRow, killPanel)
	bodyRow = lipgloss.NewStyle().Width(w).Height(ly.BodyHeight).Background(ColorBg).Render(bodyRow)

	events := m.state.GetEvents(100)
	logPanel := RenderLiveLog(events, w, ly.LogHeight)

	// Glitch alert bar replaces the status bar for brief critical-finding flashes
	var statusBar string
	if m.state.IsGlitchActive() {
		alertMsg := "  ⚠  CRITICAL THREAT DETECTED — ATTACK PATH ACTIVE  ⚠  "
		pad := w - lipgloss.Width(alertMsg)
		if pad > 0 {
			alertMsg += strings.Repeat("─", pad)
		}
		statusBar = lipgloss.NewStyle().
			Background(ColorBloodRed).
			Foreground(lipgloss.Color("#000000")).
			Bold(true).
			Width(w).
			Render(alertMsg)
	} else {
		statusBar = m.renderDashboardStatusBar(w)
	}

	footer := lipgloss.JoinVertical(lipgloss.Left, logPanel, statusBar)
	footer = lipgloss.NewStyle().Width(w).Height(ly.FooterHeight).Background(ColorBg).Render(footer)

	full := lipgloss.JoinVertical(lipgloss.Left, headerPanel, bodyRow, footer)
	return RootStyle.Width(w).Height(h).Render(full)
}

func (m AppModel) renderConfigView() string {
	w := m.width
	h := m.height

	headerPanel, headerHeight := m.renderHeader(w)
	statusHeight := 1
	bodyHeight := h - headerHeight - statusHeight
	if bodyHeight < 1 {
		bodyHeight = 1
	}

	configPanel := RenderConfigPanel(m.state, &m.config, w, bodyHeight)
	configPanel = lipgloss.NewStyle().Width(w).Height(bodyHeight).Background(ColorBg).Render(configPanel)
	statusBar := m.renderConfigStatusBar(w)
	full := lipgloss.JoinVertical(lipgloss.Left, headerPanel, configPanel, statusBar)
	return RootStyle.Width(w).Height(h).Render(full)
}

func (m AppModel) renderThreatOverviewPanel(width, height int) string {
	var b strings.Builder

	w := width - 4
	h := height - 2
	if w < 1 {
		w = 1
	}
	if h < 1 {
		h = 1
	}

	scan := m.state.CurrentScan
	entryCount := len(m.state.EntryPoints)
	crownCount := len(m.state.CrownJewels)
	markerCount := len(m.state.GeoMarkers)
	events := m.state.GetEvents(1)
	lastError, _ := m.state.GetLastError()

	header := "THREAT OVERVIEW"
	if markerCount > 0 {
		header += "  " + DimStyle.Render(fmt.Sprintf("[%d markers]", markerCount))
	}
	b.WriteString(PanelHeader.Render(header))
	b.WriteString("\n")
	b.WriteString(renderConfigSectionLine("RUNTIME", w))
	b.WriteString("\n")
	b.WriteString(fmt.Sprintf("  %s %s   %s %s\n",
		DimStyle.Render("scan:"),
		renderScanStatus(scan.Status),
		DimStyle.Render("ws:"),
		renderServerStatus(m.state.ServerStatus),
	))
	stage := strings.TrimSpace(scan.Stage)
	if stage == "" {
		stage = "idle"
	}
	b.WriteString(fmt.Sprintf("  %s %s   %s %.0fs\n",
		DimStyle.Render("stage:"),
		HighlightStyle.Render(truncate(stage, 18)),
		DimStyle.Render("elapsed:"),
		scan.ElapsedSeconds,
	))
	b.WriteString("\n")
	b.WriteString(renderConfigSectionLine("GRAPH", w))
	b.WriteString("\n")
	b.WriteString(fmt.Sprintf("  %s %s   %s %s   %s %s\n",
		DimStyle.Render("hosts:"),
		HighlightStyle.Render(fmt.Sprintf("%d", scan.Hosts)),
		DimStyle.Render("edges:"),
		HighlightStyle.Render(fmt.Sprintf("%d", scan.Edges)),
		DimStyle.Render("paths:"),
		renderDangerCount(len(m.state.KillChains)),
	))
	b.WriteString(fmt.Sprintf("  %s %s   %s %s   %s %s\n",
		DimStyle.Render("entry:"),
		HighlightStyle.Render(fmt.Sprintf("%d", entryCount)),
		DimStyle.Render("crown:"),
		HighlightStyle.Render(fmt.Sprintf("%d", crownCount)),
		DimStyle.Render("findings:"),
		renderDangerCount(scan.Findings),
	))
	b.WriteString("\n")
	b.WriteString(renderConfigSectionLine("SIGNAL", w))
	b.WriteString("\n")
	if len(events) > 0 {
		ev := events[0]
		msg := strings.TrimSpace(ev.Message)
		if msg == "" {
			msg = "awaiting event payload"
		}
		b.WriteString(fmt.Sprintf("  %s %s\n",
			DimStyle.Render("last:"),
			HighlightStyle.Render(truncate(ev.Type, w-10)),
		))
		b.WriteString(fmt.Sprintf("  %s %s\n",
			DimStyle.Render("msg:"),
			BaseStyle.Render(truncate(msg, w-10)),
		))
	} else {
		b.WriteString(DimStyle.Render("  no live events yet"))
		b.WriteString("\n")
	}
	if lastError != "" {
		b.WriteString(fmt.Sprintf("  %s %s\n",
			StatusError.Render("error:"),
			BaseStyle.Render(truncate(lastError, w-10)),
		))
	} else {
		b.WriteString(fmt.Sprintf("  %s %s\n",
			DimStyle.Render("storage:"),
			HighlightStyle.Render(strings.ToUpper(m.state.StorageMode)),
		))
	}

	// ── OFFENSIVE section: baseline vs post-offensive delta + tool state ──
	impact := m.state.GetImpact()
	runningTools := []string{}
	for _, t := range m.state.Tools {
		if t.Running {
			runningTools = append(runningTools, t.Name)
		}
	}
	if impact.PostChains > 0 || impact.BaselineChains > 0 || len(runningTools) > 0 {
		b.WriteString("\n")
		b.WriteString(renderConfigSectionLine("OFFENSIVE", w))
		b.WriteString("\n")
		deltaTxt := fmt.Sprintf("%d → %d", impact.BaselineChains, impact.PostChains)
		newTxt := DimStyle.Render("+0")
		if impact.NewChains > 0 {
			newTxt = StatusWarning.Render(fmt.Sprintf("+%d new", impact.NewChains))
		}
		b.WriteString(fmt.Sprintf("  %s %s   %s %s\n",
			DimStyle.Render("chains:"),
			HighlightStyle.Render(deltaTxt),
			DimStyle.Render("Δ:"),
			newTxt,
		))
		b.WriteString(fmt.Sprintf("  %s %s   %s %s\n",
			DimStyle.Render("+hosts:"),
			HighlightStyle.Render(fmt.Sprintf("%d", impact.HostsAdded)),
			DimStyle.Render("+edges:"),
			HighlightStyle.Render(fmt.Sprintf("%d", impact.EdgesAdded)),
		))
		runLabel := DimStyle.Render("idle")
		if len(runningTools) > 0 {
			runLabel = StatusRunning.Render("▶ " + strings.Join(runningTools, ","))
		}
		b.WriteString(fmt.Sprintf("  %s %s\n",
			DimStyle.Render("tools:"),
			truncate(runLabel, w-12),
		))
	}

	// ── FINDINGS section: most recent N from offensive tools ──
	findings := m.state.GetFindings(4)
	if len(findings) > 0 {
		b.WriteString("\n")
		b.WriteString(renderConfigSectionLine("FINDINGS", w))
		b.WriteString("\n")
		// Show newest at top
		for i := len(findings) - 1; i >= 0; i-- {
			f := findings[i]
			toolTag := categoryStyle(f.Tool).Render(fmt.Sprintf("%-9s", truncate(f.Tool, 9)))
			body := f.Narrative
			if body == "" {
				body = f.Technical
			}
			body = truncate(body, w-14)
			b.WriteString(fmt.Sprintf("  %s %s\n", toolTag, BaseStyle.Render(body)))
		}
	}

	content := truncateLines(b.String(), h)
	return PanelBorder.Width(w).Height(h).Render(content)
}

func (m AppModel) renderHeader(w int) (string, int) {
	gordianArt := [5]string{
		"  ___               _ _                     ",
		" / ___| ___  _ __ __| (_) __ _ _ __         ",
		"| |  _ / _ \\| '__/ _` | |/ _` | '_ \\        ",
		"| |_| | (_) | | | (_| | | (_| | | | |       ",
		" \\____|\\___/|_|  \\__,_|_|\\__,_|_| |_|       ",
	}
	swordHalf := [5]string{
		"",
		"         /\\",
		"   O===[ ======================-",
		"         \\/",
		"",
	}

	// Scan pulse indicator
	var scanIndicator string
	if m.state.CurrentScan.Status == "running" {
		scanIndicator = ScanPulseActive.Render("  ◉ SCANNING")
	} else {
		scanIndicator = ScanPulseIdle.Render("  ○ IDLE")
	}

	titleBold := lipgloss.NewStyle().Foreground(ColorNeonCyan).Bold(true).Background(ColorBg)
	titleDim := lipgloss.NewStyle().Foreground(ColorDimCyan).Background(ColorBg)

	var hLines [7]string
	for i := 0; i < 5; i++ {
		hLines[i] = titleBold.Render(gordianArt[i]) +
			titleDim.Render(swordHalf[i])
	}

	// Dynamic-width separator
	sepWidth := w - 4
	if sepWidth < 10 {
		sepWidth = 10
	}
	hLines[5] = titleDim.Render("  " + strings.Repeat("─", sepWidth))

	subtitle := "  ─── Attack Path Intelligence  ·  Kill Chain Analysis  ·  CVE Mapping  ───"
	hLines[6] = titleDim.Render(subtitle) + scanIndicator

	headerPanel := lipgloss.NewStyle().Width(w).Background(ColorBg).
		Render(strings.Join(hLines[:], "\n"))
	return headerPanel, 7
}

func (m AppModel) renderDashboardStatusBar(width int) string {
	// WS indicator
	var wsIcon string
	if m.state.IsWSConnected() {
		wsIcon = StatusOK.Render("●") + DimStyle.Render(" WS")
	} else {
		wsIcon = StatusError.Render("○") + DimStyle.Render(" WS")
	}

	// Scan status + inline progress
	scan := m.state.CurrentScan
	scanPart := renderScanStatus(scan.Status)
	if scan.Status == "running" {
		pct := int(scan.ProgressPercent)
		if pct < 0 {
			pct = 0
		}
		if pct > 100 {
			pct = 100
		}
		filled := pct * 8 / 100
		bar := StatusOK.Render(strings.Repeat("█", filled)) +
			DimStyle.Render(strings.Repeat("░", 8-filled))
		scanPart += DimStyle.Render(" [") + bar + DimStyle.Render("]") +
			HighlightStyle.Render(fmt.Sprintf(" %d%%", pct))
	}

	// Storage
	var storageIcon string
	if m.state.StorageMode == "ram" {
		storageIcon = StatusWarning.Render("⚡") + DimStyle.Render("RAM")
	} else {
		storageIcon = StatusOK.Render("💾") + DimStyle.Render("SQLite")
	}

	// Key hints (right side)
	keys := fmt.Sprintf("%s scan  %s stop  %s config  %s refresh  %s quit",
		KeyStyle.Render("s"),
		KeyStyle.Render("x"),
		KeyStyle.Render("c"),
		KeyStyle.Render("r"),
		KeyStyle.Render("q"),
	)

	left := fmt.Sprintf("  %s   %s   %s  ", wsIcon, scanPart, storageIcon)
	right := " " + keys + "  "

	gap := width - lipgloss.Width(left) - lipgloss.Width(right)
	if gap < 0 {
		gap = 0
	}

	bar := left + strings.Repeat(" ", gap) + right
	return lipgloss.NewStyle().
		Background(lipgloss.Color("#0a0a0a")).
		Foreground(ColorDimWhite).
		Width(width).
		Render(bar)
}

// ── Commands (side effects) ─────────────────────────────────────────

func (m AppModel) renderConfigStatusBar(width int) string {
	left := fmt.Sprintf("  %s   %s   %s %d  ",
		DimStyle.Render("view:"),
		HighlightStyle.Render("CONFIG"),
		DimStyle.Render("jobs:"),
		m.state.MaxConcurrent,
	)
	right := fmt.Sprintf(" %s dashboard  %s back  %s save/load  %s quit  ",
		KeyStyle.Render("c"),
		KeyStyle.Render("esc"),
		KeyStyle.Render("w/o/z"),
		KeyStyle.Render("q"),
	)

	gap := width - lipgloss.Width(left) - lipgloss.Width(right)
	if gap < 0 {
		gap = 0
	}

	bar := left + strings.Repeat(" ", gap) + right
	return lipgloss.NewStyle().
		Background(lipgloss.Color("#0a0a0a")).
		Foreground(ColorDimWhite).
		Width(width).
		Render(bar)
}

func (m AppModel) connectWS() tea.Cmd {
	return func() tea.Msg {
		err := m.wsClient.ConnectWithRetry(3)
		if err != nil {
			return scanErrorMsg{Err: fmt.Errorf("WebSocket: %w", err)}
		}
		return wsConnectedMsg{}
	}
}

func (m AppModel) listenWS() tea.Cmd {
	client := m.wsClient
	return func() tea.Msg {
		select {
		case ev, ok := <-client.Events:
			if !ok {
				return wsDisconnectedMsg{}
			}
			// Explicit WSEvent → LiveEvent conversion
			return wsEventMsg{Event: state.LiveEvent{
				Type:      ev.Type,
				Timestamp: ev.Timestamp,
				Tool:      ev.Tool,
				Level:     ev.Level,
				Message:   ev.Message,
				Payload:   ev.Payload,
				Sequence:  ev.Sequence,
				ScanID:    ev.ScanID,
			}}
		case <-client.Done:
			return wsDisconnectedMsg{}
		}
	}
}

func (m AppModel) fetchServerInfo() tea.Cmd {
	return func() tea.Msg {
		info, err := m.client.GetInfo()
		if err != nil {
			return scanErrorMsg{Err: err}
		}
		return serverInfoMsg{
			Version: info.Version,
			Status:  info.Status,
			Storage: info.StorageBackend,
			MaxScan: info.MaxConcurrent,
		}
	}
}

func (m AppModel) fetchScanStatus() tea.Cmd {
	return func() tea.Msg {
		resp, err := m.client.GetScanStatus("")
		if err != nil {
			return scanErrorMsg{Err: err}
		}
		return scanStatusMsg{
			ScanID:          resp.ScanID,
			Status:          resp.Status,
			Stage:           resp.Progress.Stage,
			ProgressPercent: resp.Progress.Percent,
			Message:         resp.Progress.Message,
			ElapsedSeconds:  resp.ElapsedSeconds,
			Hosts:           resp.Stats.Hosts,
			Edges:           resp.Stats.Edges,
			KillChains:      resp.Stats.KillChains,
			Findings:        resp.Stats.Findings,
			Patches:         resp.Stats.Patches,
		}
	}
}

func (m AppModel) startScan() tea.Cmd {
	return func() tea.Msg {
		cfg := m.state.GetScanConfig()

		b := newScanBuilder()
		b.withString(&b.req.Target, cfg.Target).
			withString(&b.req.NetworkFile, cfg.NetworkFile).
			withString(&b.req.CVEFile, cfg.CVEFile).
			withString(&b.req.OutputDir, cfg.OutputDir).
			withString(&b.req.OffensiveMode, cfg.OffensiveMode).
			withString(&b.req.OffensiveSpeed, cfg.OffensiveSpeed).
			withString(&b.req.OffensiveIntensity, cfg.OffensiveIntensity).
			withTools(cfg, m.state.Tools).
			withToolOverrides(cfg)

		b.withOptionalInt(cfg.MaxNmapRate, "max_nmap_rate", func(v *int) { b.req.MaxNmapRate = v }).
			withOptionalInt(cfg.MaxFfufThreads, "max_ffuf_threads", func(v *int) { b.req.MaxFfufThreads = v }).
			withOptionalInt(cfg.MaxNucleiRate, "max_nuclei_rate", func(v *int) { b.req.MaxNucleiRate = v }).
			withOptionalInt(cfg.MaxTotalTargets, "max_total_targets", func(v *int) { b.req.MaxTotalTargets = v }).
			withOptionalInt(cfg.MaxTotalCommands, "max_total_commands", func(v *int) { b.req.MaxTotalCommands = v }).
			withOptionalInt(cfg.MaxFindings, "max_findings", func(v *int) { b.req.MaxFindings = v }).
			withOptionalInt(cfg.MaxRunSeconds, "max_run_seconds", func(v *int) { b.req.MaxRunSeconds = v }).
			withOptionalInt(cfg.TopPatches, "top_patches", func(v *int) { b.req.TopPatches = *v }).
			withOptionalInt(cfg.AssetCVEMinScore, "asset_cve_min_score", func(v *int) { b.req.AssetCVEMinScore = *v }).
			withOptionalInt(cfg.AssetCVEKeepTop, "asset_cve_keep_top", func(v *int) { b.req.AssetCVEKeepTop = *v })

		b.withOptionalBool(cfg.CVEAutoDownload, "cve_auto_download", func(v *bool) { b.req.CVEAutoDownload = v }).
			withOptionalBool(cfg.RunRemediation, "run_remediation", func(v *bool) { b.req.RunRemediation = *v }).
			withOptionalBool(cfg.AssetAwareCVEs, "asset_aware_cves", func(v *bool) { b.req.AssetAwareCVEs = *v }).
			withOptionalBool(cfg.BugbountyMode, "bugbounty_mode", func(v *bool) { b.req.BugbountyMode = v }).
			withOptionalBool(cfg.FullControl, "full_control", func(v *bool) { b.req.FullControl = v })

		if v := optionalStringPtr(cfg.CVEProfile); v != nil {
			b.req.CVEProfile = v
		}
		if v := optionalStringPtr(cfg.CVESyncPolicy); v != nil {
			b.req.CVESyncPolicy = v
		}
		if v := optionalStringPtr(cfg.WordlistProfile); v != nil {
			b.req.WordlistProfile = v
		}
		if v := optionalStringPtr(cfg.FfufWordlist); v != nil {
			b.req.FfufWordlist = v
		}

		req, err := b.build()
		if err != nil {
			return scanErrorMsg{Err: err}
		}

		resp, err := m.client.StartScan(req)
		if err != nil {
			return scanErrorMsg{Err: err}
		}
		return scanStartedMsg{ScanID: resp.ScanID}
	}
}

// applyLiveEvent routes a WS event into mutable AppState without waiting for
// the next REST poll. Backend events follow a stable naming scheme:
//
//	offensive.tool_start / offensive.tool_done   → tool Running flag
//	offensive.finding                            → finding list + counter
//	pipeline.offensive.impact                    → OffensiveImpact snapshot
//	pipeline.transform.graph_built               → hosts/edges counters
//	pipeline.transform.paths_built               → kill chain refresh
//	pipeline.done                                → final refresh (counts + reports)
//
// Returns an optional follow-up Cmd (e.g. a graph refetch) when WS data
// alone isn't enough to render the new state.
func (m AppModel) applyLiveEvent(ev state.LiveEvent) tea.Cmd {
	switch ev.Type {
	case "offensive.tool_start":
		m.state.SetToolRunning(ev.Tool, true)

	case "offensive.tool_done":
		m.state.SetToolRunning(ev.Tool, false)

	case "offensive.finding":
		f := state.Finding{
			Tool:      ev.Tool,
			Technical: ev.Message,
		}
		if v, ok := ev.Payload["narrative"].(string); ok {
			f.Narrative = v
		}
		if v, ok := ev.Payload["confidence"].(float64); ok {
			f.Confidence = v
		}
		if v, ok := ev.Payload["target_host_id"].(string); ok {
			f.Target = v
		}
		m.state.PushFinding(f)
		// Bump the live counter so threat overview reflects the new finding
		// immediately, even before the next status poll arrives.
		info := m.state.CurrentScan
		info.Findings++
		m.state.SetScanInfo(info)

	case "pipeline.offensive.impact":
		impact := state.OffensiveImpact{}
		if v, ok := ev.Payload["baseline_chains"].(float64); ok {
			impact.BaselineChains = int(v)
		}
		if v, ok := ev.Payload["post_chains"].(float64); ok {
			impact.PostChains = int(v)
		}
		if v, ok := ev.Payload["new_chains"].(float64); ok {
			impact.NewChains = int(v)
		}
		if v, ok := ev.Payload["edges_added"].(float64); ok {
			impact.EdgesAdded = int(v)
		}
		if v, ok := ev.Payload["hosts_added"].(float64); ok {
			impact.HostsAdded = int(v)
		}
		if raw, ok := ev.Payload["new_target_hosts"].([]interface{}); ok {
			hosts := make([]string, 0, len(raw))
			for _, item := range raw {
				if s, ok := item.(string); ok {
					hosts = append(hosts, s)
				}
			}
			impact.NewTargetHosts = hosts
		}
		m.state.SetImpact(impact)

	case "pipeline.transform.graph_built":
		info := m.state.CurrentScan
		if v, ok := ev.Payload["nodes"].(float64); ok {
			info.Hosts = int(v)
		}
		if v, ok := ev.Payload["edges"].(float64); ok {
			info.Edges = int(v)
		}
		m.state.SetScanInfo(info)

	case "pipeline.transform.paths_built":
		info := m.state.CurrentScan
		if v, ok := ev.Payload["kill_chains"].(float64); ok {
			info.KillChains = int(v)
		}
		m.state.SetScanInfo(info)
		// Chain set may have changed — refetch so the kill-chain panel renders
		// the new entries (we only got the count via WS, not the data).
		return m.fetchKillChains()

	case "pipeline.done":
		// Final settling: pull fresh graph + chains + findings in one go.
		return tea.Batch(
			m.fetchScanStatus(),
			m.fetchGraph(),
			m.fetchKillChains(),
			m.fetchFindings(),
		)
	}
	return nil
}

func (m AppModel) cancelScan(scanID string) tea.Cmd {
	client := m.client
	return func() tea.Msg {
		resp, err := client.CancelScan(scanID)
		if err != nil {
			return scanErrorMsg{Err: fmt.Errorf("cancel: %w", err)}
		}
		return scanCancelledMsg{ScanID: resp.ScanID}
	}
}

func (m AppModel) saveProfile() tea.Cmd {
	cfg := m.state.GetScanConfig()
	path := strings.TrimSpace(cfg.ProfilePath)
	if path == "" {
		path = "gordian_profile.json"
	}
	state := m.state
	return func() tea.Msg {
		if err := state.SaveProfile(path); err != nil {
			return scanErrorMsg{Err: fmt.Errorf("save profile: %w", err)}
		}
		abs, _ := filepath.Abs(path)
		return profileSavedMsg{Path: abs}
	}
}

func (m AppModel) loadProfile() tea.Cmd {
	cfg := m.state.GetScanConfig()
	path := strings.TrimSpace(cfg.ProfilePath)
	if path == "" {
		path = "gordian_profile.json"
	}
	state := m.state
	return func() tea.Msg {
		if _, err := os.Stat(path); err != nil {
			return scanErrorMsg{Err: fmt.Errorf("no profile at %s (Ctrl+S to create one)", path)}
		}
		if err := state.LoadProfile(path); err != nil {
			return scanErrorMsg{Err: fmt.Errorf("load profile: %w", err)}
		}
		abs, _ := filepath.Abs(path)
		return profileLoadedMsg{Path: abs}
	}
}

func (m AppModel) saveReport() tea.Cmd {
	cfg := m.state.GetScanConfig()
	outDir := cfg.OutputDir
	if outDir == "" {
		outDir = "reports"
	}
	return func() tea.Msg {
		abs, err := filepath.Abs(outDir)
		if err != nil {
			return scanErrorMsg{Err: fmt.Errorf("resolve report dir: %w", err)}
		}
		md := filepath.Join(abs, "attack_paths.md")
		if _, statErr := os.Stat(md); statErr != nil {
			return scanErrorMsg{Err: fmt.Errorf("no report at %s (run a scan first)", md)}
		}
		return reportSavedMsg{Path: md}
	}
}

func parseOptionalInt(raw string) (*int, error) {
	v := strings.TrimSpace(raw)
	if v == "" {
		return nil, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return nil, fmt.Errorf("expected integer, got %q", v)
	}
	return &n, nil
}

func parseOptionalBool(raw string) (*bool, error) {
	v := strings.ToLower(strings.TrimSpace(raw))
	if v == "" {
		return nil, nil
	}
	switch v {
	case "1", "true", "yes", "y", "on":
		b := true
		return &b, nil
	case "0", "false", "no", "n", "off":
		b := false
		return &b, nil
	default:
		return nil, fmt.Errorf("expected boolean, got %q", raw)
	}
}

func optionalStringPtr(raw string) *string {
	v := strings.TrimSpace(raw)
	if v == "" {
		return nil
	}
	return &v
}

func parseCSVList(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		v := strings.TrimSpace(p)
		if v == "" {
			continue
		}
		out = append(out, strings.ToLower(v))
	}
	return out
}

func splitCommandLine(raw string) ([]string, error) {
	text := strings.TrimSpace(raw)
	if text == "" {
		return nil, nil
	}

	args := []string{}
	var current strings.Builder
	var quote rune
	escaped := false

	for _, r := range text {
		switch {
		case escaped:
			current.WriteRune(r)
			escaped = false
		case r == '\\':
			escaped = true
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				current.WriteRune(r)
			}
		case r == '"' || r == '\'':
			quote = r
		case unicode.IsSpace(r):
			if current.Len() > 0 {
				args = append(args, current.String())
				current.Reset()
			}
		default:
			current.WriteRune(r)
		}
	}

	if escaped {
		current.WriteRune('\\')
	}
	if quote != 0 {
		return nil, fmt.Errorf("unterminated quote")
	}
	if current.Len() > 0 {
		args = append(args, current.String())
	}
	return args, nil
}

func buildToolBinMap(cfg state.ScanConfig) map[string]string {
	bins := map[string]string{}
	for tool, value := range map[string]string{
		"nmap":      cfg.NmapBin,
		"ffuf":      cfg.FfufBin,
		"nuclei":    cfg.NucleiBin,
		"subfinder": cfg.SubfinderBin,
		"httpx":     cfg.HttpxBin,
		"katana":    cfg.KatanaBin,
		"gitleaks":  cfg.GitleaksBin,
		"gowitness": cfg.GowitnessBin,
	} {
		trimmed := strings.TrimSpace(value)
		if trimmed != "" {
			bins[tool] = trimmed
		}
	}
	if len(bins) == 0 {
		return nil
	}
	return bins
}

func buildToolArgMap(cfg state.ScanConfig, command bool) (map[string][]string, error) {
	values := map[string]string{}
	if command {
		values = map[string]string{
			"nmap":      cfg.NmapCommand,
			"ffuf":      cfg.FfufCommand,
			"nuclei":    cfg.NucleiCommand,
			"subfinder": cfg.SubfinderCommand,
			"httpx":     cfg.HttpxCommand,
			"katana":    cfg.KatanaCommand,
			"gitleaks":  cfg.GitleaksCommand,
			"gowitness": cfg.GowitnessCommand,
		}
	} else {
		values = map[string]string{
			"nmap":      cfg.NmapExtraArgs,
			"ffuf":      cfg.FfufExtraArgs,
			"nuclei":    cfg.NucleiExtraArgs,
			"subfinder": cfg.SubfinderExtraArgs,
			"httpx":     cfg.HttpxExtraArgs,
			"katana":    cfg.KatanaExtraArgs,
			"gitleaks":  cfg.GitleaksExtraArgs,
			"gowitness": cfg.GowitnessExtraArgs,
		}
	}

	result := map[string][]string{}
	for tool, raw := range values {
		tokens, err := splitCommandLine(raw)
		if err != nil {
			fieldName := tool + " extra args"
			if command {
				fieldName = tool + " command"
			}
			return nil, fmt.Errorf("invalid %s: %w", fieldName, err)
		}
		if len(tokens) > 0 {
			result[tool] = tokens
		}
	}

	if len(result) == 0 {
		return nil, nil
	}
	return result, nil
}

func (m AppModel) fetchGraph() tea.Cmd {
	return func() tea.Msg {
		resp, err := m.client.GetGraph("")
		if err != nil {
			return scanErrorMsg{Err: err}
		}
		hosts := make([]state.HostNode, len(resp.Hosts))
		for i, h := range resp.Hosts {
			hosts[i] = state.HostNode{
				ID: h.ID, Hostname: h.Hostname, IPAddress: h.IPAddress,
				Segment: h.Segment, OS: h.OS,
				IsAttackerEntry: h.IsAttackerEntry, IsCrownJewel: h.IsCrownJewel,
			}
		}
		edges := make([]state.GraphEdge, len(resp.Edges))
		for i, e := range resp.Edges {
			edges[i] = state.GraphEdge{
				Source: e.Source, Target: e.Target, Port: e.Port,
				CVEID: e.CVEID, Cost: e.Cost, CVSS: e.CVSS, Category: e.Category,
			}
		}
		return graphDataMsg{
			Hosts: hosts, Edges: edges,
			EntryPoints: resp.EntryPoints, CrownJewels: resp.CrownJewels,
		}
	}
}

func (m AppModel) fetchKillChains() tea.Cmd {
	return func() tea.Msg {
		chains, err := m.client.GetKillChains("")
		if err != nil {
			return scanErrorMsg{Err: err}
		}
		result := make([]state.KillChain, len(chains))
		for i, c := range chains {
			result[i] = state.KillChain{
				TargetHostname: c.TargetHostname,
				RiskScore:      c.RiskScore,
				Hops:           c.Hops,
				ExploitChain:   c.ExploitChain,
			}
		}
		return killChainMsg(result)
	}
}

func (m AppModel) fetchFindings() tea.Cmd {
	return func() tea.Msg {
		resp, err := m.client.GetFindings("")
		if err != nil {
			return scanErrorMsg{Err: err}
		}
		out := make([]state.Finding, len(resp.Findings))
		for i, f := range resp.Findings {
			out[i] = state.Finding{
				Tool:       f.Tool,
				Type:       f.Type,
				Technical:  f.Technical,
				Narrative:  f.Narrative,
				Confidence: f.Confidence,
				Severity:   f.Severity,
				Target:     f.Target,
				Metadata:   f.Metadata,
			}
		}
		return findingsSnapshotMsg(out)
	}
}
