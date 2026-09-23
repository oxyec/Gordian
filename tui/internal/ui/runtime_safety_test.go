package ui

import (
	"strings"
	"sync"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"gordian-tui/internal/state"
)

func TestFormatLogEventShortTimestampNoPanic(t *testing.T) {
	ev := state.LiveEvent{
		Timestamp: "2026-04-18",
		Level:     "info",
		Type:      "pipeline.tick",
		Tool:      "hub",
		Message:   "ok",
	}

	assertNotPanics(t, func() {
		out := formatLogEvent(ev, 80)
		if out == "" {
			t.Fatal("expected formatted log line")
		}
	})
}

func TestFormatLogEventNarrowWidthNoPanic(t *testing.T) {
	ev := state.LiveEvent{
		Timestamp: "12:34:56",
		Level:     "warning",
		Type:      "offensive.finding",
		Tool:      "nuclei",
		Message:   "this is a very long message that must be truncated safely",
	}

	assertNotPanics(t, func() {
		out := formatLogEvent(ev, 10)
		if out == "" {
			t.Fatal("expected formatted log line")
		}
	})
}

func TestRenderConfigPanelOutOfRangeValuesNoPanic(t *testing.T) {
	appState := state.NewAppState("http://localhost:8000")
	config := NewConfigModel(appState.GetScanConfig())
	appState.MaxConcurrent = -5
	appState.CurrentScan.ProgressPercent = 150

	assertNotPanics(t, func() {
		out := RenderConfigPanel(appState, &config, 80, 30)
		if out == "" {
			t.Fatal("expected rendered config panel")
		}
	})
}

func TestHandleKeyQQuitsInDashboard(t *testing.T) {
	m := NewAppModel("http://localhost:8000", "ws://localhost:8000/api/v1/live")
	m.phase = "dashboard"

	_, cmd := m.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
	if cmd == nil {
		t.Fatal("expected quit command")
	}

	if _, ok := cmd().(tea.QuitMsg); !ok {
		t.Fatal("expected tea.QuitMsg for q key")
	}
}

func TestConfigEditModeConsumesQAndUpdatesState(t *testing.T) {
	m := NewAppModel("http://localhost:8000", "ws://localhost:8000/api/v1/live")
	m.phase = "dashboard"
	m.activePanel = 2 // config panel

	model, cmd := m.handleKey(tea.KeyMsg{Type: tea.KeyEnter})
	if cmd != nil {
		t.Fatal("expected no quit command when entering edit mode")
	}
	updated, ok := model.(AppModel)
	if !ok {
		t.Fatal("expected AppModel after enter key")
	}

	model, cmd = updated.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
	if cmd != nil {
		if _, isQuit := cmd().(tea.QuitMsg); isQuit {
			t.Fatal("did not expect quit command while config field is editing")
		}
	}
	updated, ok = model.(AppModel)
	if !ok {
		t.Fatal("expected AppModel after typing in edit mode")
	}

	if got := updated.state.GetScanConfig().Target; got != "q" {
		t.Fatalf("expected target to be updated to 'q', got %q", got)
	}
}

func TestConfigEditModeAllowsNumericInput(t *testing.T) {
	m := NewAppModel("http://localhost:8000", "ws://localhost:8000/api/v1/live")
	m.phase = "dashboard"
	m.activePanel = 2

	model, _ := m.handleKey(tea.KeyMsg{Type: tea.KeyEnter})
	updated, ok := model.(AppModel)
	if !ok {
		t.Fatal("expected AppModel after enter key")
	}

	model, _ = updated.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'5'}})
	updated, ok = model.(AppModel)
	if !ok {
		t.Fatal("expected AppModel after numeric input")
	}

	if got := updated.state.GetScanConfig().Target; got != "5" {
		t.Fatalf("expected target to include numeric input, got %q", got)
	}
	if updated.config.ActiveMenu != MenuTargetMode {
		t.Fatalf("expected active menu to remain target mode while editing, got %d", updated.config.ActiveMenu)
	}
}

func TestConfigMenuNineSelectsProfiles(t *testing.T) {
	appState := state.NewAppState("http://localhost:8000")
	config := NewConfigModel(appState.GetScanConfig())

	handled, _ := config.HandleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'9'}}, appState)
	if !handled {
		t.Fatal("expected key 9 to be handled by config model")
	}
	if config.ActiveMenu != MenuProfiles {
		t.Fatalf("expected active menu profiles, got %d", config.ActiveMenu)
	}
}

func TestConfigToolFilterShowsOnlyEnabledTools(t *testing.T) {
	appState := state.NewAppState("http://localhost:8000")
	config := NewConfigModel(appState.GetScanConfig())
	config.ActiveMenu = MenuToolBin

	handled, _ := config.HandleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'f'}}, appState)
	if !handled {
		t.Fatal("expected f to toggle tool filter")
	}
	if !config.ShowActiveToolsOnly {
		t.Fatal("expected active-tool filter to be enabled")
	}

	out := RenderConfigPanel(appState, &config, 120, 40)
	if strings.Contains(out, "subfinder bin") {
		t.Fatal("expected disabled tool field to be hidden when active-tool filter is on")
	}
	if !strings.Contains(out, "nmap bin") {
		t.Fatal("expected enabled tool field to remain visible")
	}
}

func TestConfigPanelTabCyclesGlobalPanel(t *testing.T) {
	m := NewAppModel("http://localhost:8000", "ws://localhost:8000/api/v1/live")
	m.phase = "dashboard"
	m.activePanel = 2

	model, cmd := m.handleKey(tea.KeyMsg{Type: tea.KeyTab})
	if cmd != nil {
		t.Fatal("expected no command from tab panel switch")
	}

	updated, ok := model.(AppModel)
	if !ok {
		t.Fatal("expected AppModel after tab panel switch")
	}
	if updated.activePanel != 0 {
		t.Fatalf("expected tab to switch from config panel to map panel, got %d", updated.activePanel)
	}
}

func TestDashboardShortcutCOpensConfigPanel(t *testing.T) {
	m := NewAppModel("http://localhost:8000", "ws://localhost:8000/api/v1/live")
	m.phase = "dashboard"

	model, cmd := m.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'c'}})
	if cmd != nil {
		t.Fatal("expected no command when switching to config panel")
	}

	updated, ok := model.(AppModel)
	if !ok {
		t.Fatal("expected AppModel after config shortcut")
	}
	if updated.activePanel != 2 {
		t.Fatalf("expected config panel to become active, got %d", updated.activePanel)
	}
	if updated.state.ActiveView != "config" {
		t.Fatalf("expected config view to be selected, got %q", updated.state.ActiveView)
	}
}

func TestConfigShortcutTogglesBackToDashboard(t *testing.T) {
	m := NewAppModel("http://localhost:8000", "ws://localhost:8000/api/v1/live")
	m.phase = "dashboard"
	m.activePanel = 2
	m.state.ActiveView = "config"

	model, cmd := m.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'c'}})
	if cmd != nil {
		t.Fatal("expected no command when leaving config view")
	}

	updated, ok := model.(AppModel)
	if !ok {
		t.Fatal("expected AppModel after config toggle")
	}
	if updated.activePanel != 0 {
		t.Fatalf("expected dashboard to become active, got %d", updated.activePanel)
	}
	if updated.state.ActiveView != "dashboard" {
		t.Fatalf("expected dashboard view, got %q", updated.state.ActiveView)
	}
}

func TestViewRendersFullScreenConfigWithoutToolbox(t *testing.T) {
	m := NewAppModel("http://localhost:8000", "ws://localhost:8000/api/v1/live")
	m.phase = "dashboard"
	m.width = 120
	m.height = 40
	m.activePanel = 2
	m.state.ActiveView = "config"

	out := m.View()
	if !strings.Contains(out, "COMMAND CONFIG") {
		t.Fatal("expected full-screen config view to render config content")
	}
	if strings.Contains(out, "TOOLBOX") {
		t.Fatal("did not expect toolbox content in full-screen config view")
	}
}

func TestDashboardViewNoLongerRendersToolbox(t *testing.T) {
	m := NewAppModel("http://localhost:8000", "ws://localhost:8000/api/v1/live")
	m.phase = "dashboard"
	m.width = 120
	m.height = 40

	out := m.View()
	if strings.Contains(out, "TOOLBOX") {
		t.Fatal("did not expect toolbox panel in dashboard view")
	}
	if !strings.Contains(out, "THREAT OVERVIEW") {
		t.Fatal("expected revised dashboard overview panel to render")
	}
	if strings.Index(out, "THREAT OVERVIEW") > strings.Index(out, "GLOBAL THREAT MAP") {
		t.Fatal("expected threat overview to render left of the threat map")
	}
}

func TestConfigEditModeTabCyclesPanelAndStopsEditing(t *testing.T) {
	m := NewAppModel("http://localhost:8000", "ws://localhost:8000/api/v1/live")
	m.phase = "dashboard"
	m.activePanel = 2

	model, _ := m.handleKey(tea.KeyMsg{Type: tea.KeyEnter})
	updated, ok := model.(AppModel)
	if !ok {
		t.Fatal("expected AppModel after entering edit mode")
	}
	if !updated.config.Editing {
		t.Fatal("expected config edit mode to be active")
	}

	model, cmd := updated.handleKey(tea.KeyMsg{Type: tea.KeyTab})
	if cmd != nil {
		t.Fatal("expected no command from tab while leaving edit mode")
	}
	updated, ok = model.(AppModel)
	if !ok {
		t.Fatal("expected AppModel after tab from edit mode")
	}
	if updated.config.Editing {
		t.Fatal("expected tab to leave config edit mode before panel switch")
	}
	if updated.activePanel != 0 {
		t.Fatalf("expected tab to switch to map panel, got %d", updated.activePanel)
	}
}

func TestConfigPresetCanSwitchToCustomAndEdit(t *testing.T) {
	appState := state.NewAppState("http://localhost:8000")
	config := NewConfigModel(appState.GetScanConfig())
	config.ActiveMenu = MenuTargetMode
	config.FocusIndex = 1 // offensive_mode

	handled, _ := config.HandleKey(tea.KeyMsg{Type: tea.KeyLeft}, appState)
	if !handled {
		t.Fatal("expected left key to cycle selector")
	}
	if !config.CustomSelected["offensive_mode"] {
		t.Fatal("expected offensive_mode to switch into custom selector mode")
	}

	handled, _ = config.HandleKey(tea.KeyMsg{Type: tea.KeyEnter}, appState)
	if !handled {
		t.Fatal("expected enter to start editing custom selector")
	}
	if !config.Editing {
		t.Fatal("expected custom selector to enter edit mode")
	}

	handled, _ = config.HandleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'x'}}, appState)
	if !handled {
		t.Fatal("expected custom edit keystroke to be handled")
	}
	if got := appState.GetScanConfig().OffensiveMode; got != "x" {
		t.Fatalf("expected custom offensive_mode to update state, got %q", got)
	}
}

func TestConfigBooleanSelectorStaysOutOfFreeTextEdit(t *testing.T) {
	appState := state.NewAppState("http://localhost:8000")
	config := NewConfigModel(appState.GetScanConfig())
	config.ActiveMenu = MenuCVEPolicy
	config.FocusIndex = 1 // cve_auto_download

	handled, _ := config.HandleKey(tea.KeyMsg{Type: tea.KeyEnter}, appState)
	if !handled {
		t.Fatal("expected enter to be handled by selector")
	}
	if config.Editing {
		t.Fatal("expected boolean selector to stay out of free-text edit mode")
	}
	if !strings.Contains(config.StatusMessage, "left/right") {
		t.Fatalf("expected selector hint status, got %q", config.StatusMessage)
	}
}

func TestIsGlitchActiveConcurrentSafety(t *testing.T) {
	appState := state.NewAppState("http://localhost:8000")

	var wg sync.WaitGroup
	// Hammer IsGlitchActive + TriggerGlitch concurrently to detect races
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			_ = appState.IsGlitchActive()
		}()
		go func() {
			defer wg.Done()
			appState.TriggerGlitch(1)
		}()
	}
	wg.Wait()
}

func TestTinyTerminalNoPanic(t *testing.T) {
	appState := state.NewAppState("http://localhost:8000")
	config := NewConfigModel(appState.GetScanConfig())

	assertNotPanics(t, func() {
		RenderConfigPanel(appState, &config, 10, 5)
		RenderToolbox(appState.Tools, 0, false, false, 10, 5)
		RenderLiveLog(nil, 10, 5)
		RenderWorldMap(nil, 80, 20, false, 70, 30)
		RenderKillChains(nil, 10, 5)
	})
}

func TestBootModelAutoAdvance(t *testing.T) {
	m := NewBootModel()
	m.autoAdvDelay = 0 // instant for testing

	// Advance through all art + modules
	for i := 0; i < len(swordArt)+len(bootModules)+2; i++ {
		m, _ = m.Update(bootTickMsg{})
	}

	if !m.IsDone() {
		t.Fatal("expected boot to auto-advance after loading completes")
	}
}

func TestBootModelSkipWithEnter(t *testing.T) {
	m := NewBootModel()

	// Advance partially
	for i := 0; i < 5; i++ {
		m, _ = m.Update(bootTickMsg{})
	}

	// Press Enter to skip
	m, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})

	if !m.IsDone() {
		t.Fatal("expected boot to skip on Enter press")
	}
}

func TestRenderConfigPanelWithError(t *testing.T) {
	appState := state.NewAppState("http://localhost:8000")
	config := NewConfigModel(appState.GetScanConfig())
	appState.SetLastError("connection refused")

	assertNotPanics(t, func() {
		out := RenderConfigPanel(appState, &config, 80, 40)
		if out == "" {
			t.Fatal("expected rendered config panel with error")
		}
	})
}

func assertNotPanics(t *testing.T, fn func()) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("unexpected panic: %v", r)
		}
	}()
	fn()
}
