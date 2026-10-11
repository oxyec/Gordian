/*
Config panel — interactive command-center settings with multi-tab menus,
field editing, and profile save/load/reset actions.
*/
package ui

import (
	"fmt"
	"strings"
	"time"

	"gordian-tui/internal/state"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type ConfigMenu int

const (
	MenuTargetMode ConfigMenu = iota + 1
	MenuRateLimits
	MenuCVEPolicy
	MenuBudget
	MenuFlags
	MenuProfiles
)

var orderedConfigMenus = []ConfigMenu{
	MenuTargetMode,
	MenuRateLimits,
	MenuCVEPolicy,
	MenuBudget,
	MenuFlags,
	MenuProfiles,
}

var configMenuTitles = map[ConfigMenu]string{
	MenuTargetMode: "Target + Mode",
	MenuRateLimits: "Rate + Wordlists",
	MenuCVEPolicy:  "CVE Policy",
	MenuBudget:     "Budget",
	MenuFlags:      "Flags",
	MenuProfiles:   "Profiles",
}

var configMenuShortTitles = map[ConfigMenu]string{
	MenuTargetMode: "Tgt",
	MenuRateLimits: "Rate",
	MenuCVEPolicy:  "CVE",
	MenuBudget:     "Budget",
	MenuFlags:      "Flags",
	MenuProfiles:   "Profile",
}

type configField struct {
	Key         string
	Label       string
	Placeholder string
	Presets     []configPreset
	AllowCustom bool
}

type configPreset struct {
	Label string
	Value string
}

type ConfigModel struct {
	ActiveMenu     ConfigMenu
	FocusIndex     int
	ScrollOffset   int
	Editing        bool
	Inputs         map[ConfigMenu][]textinput.Model
	Fields         map[ConfigMenu][]configField
	CustomValues   map[string]string
	CustomSelected map[string]bool
	StatusMessage  string
	StatusUntil    time.Time
}

func NewConfigModel(cfg state.ScanConfig) ConfigModel {
	fields := configFieldLayout()
	inputs := make(map[ConfigMenu][]textinput.Model, len(fields))
	customValues := map[string]string{}
	customSelected := map[string]bool{}

	for _, menu := range orderedConfigMenus {
		defs := fields[menu]
		menuInputs := make([]textinput.Model, 0, len(defs))
		for _, def := range defs {
			value := getScanConfigValue(cfg, def.Key)
			in := textinput.New()
			in.Prompt = ""
			in.Placeholder = def.Placeholder
			in.CharLimit = 2048
			in.Width = 28
			in.SetValue(value)
			in.Blur()
			menuInputs = append(menuInputs, in)

			if def.AllowCustom && !configFieldValueIsPreset(def, value) {
				customValues[def.Key] = strings.TrimSpace(value)
				customSelected[def.Key] = true
			}
		}
		inputs[menu] = menuInputs
	}

	return ConfigModel{
		ActiveMenu:     MenuTargetMode,
		Inputs:         inputs,
		Fields:         fields,
		CustomValues:   customValues,
		CustomSelected: customSelected,
	}
}

func (m *ConfigModel) HandleKey(msg tea.KeyMsg, appState *state.AppState) (bool, tea.Cmd) {
	key := msg.String()

	if m.Editing {
		inputs := m.Inputs[m.ActiveMenu]
		if len(inputs) == 0 || m.FocusIndex < 0 || m.FocusIndex >= len(inputs) {
			m.Editing = false
			m.blurAllInputs()
			return true, nil
		}

		switch key {
		case "enter":
			m.Editing = false
			m.blurAllInputs()
			return true, nil
		case "esc":
			m.Editing = false
			m.blurAllInputs()
			return true, nil
		case "tab", "shift+tab":
			// Let global panel navigation handle tab once edit mode is closed.
			m.Editing = false
			m.blurAllInputs()
			return false, nil
		}

		updated, cmd := inputs[m.FocusIndex].Update(msg)
		inputs[m.FocusIndex] = updated
		m.Inputs[m.ActiveMenu] = inputs
		m.syncFocusedValueToState(appState)
		return true, cmd
	}

	if menu := menuFromKey(key); menu != 0 {
		m.ActiveMenu = menu
		m.FocusIndex = firstFieldIndex(m.Fields[m.ActiveMenu])
		m.ScrollOffset = 0
		m.Editing = false
		m.blurAllInputs()
		return true, nil
	}

	if m.ActiveMenu == MenuProfiles && !m.Editing {
		switch key {
		case "w":
			cfg := appState.GetScanConfig()
			path := strings.TrimSpace(cfg.ProfilePath)
			if path == "" {
				path = "gordian_profile.json"
				cfg.ProfilePath = path
				appState.SetScanConfig(cfg)
				m.SyncFromState(cfg)
			}
			if err := appState.SaveProfile(path); err != nil {
				m.setStatus("save failed: " + err.Error())
			} else {
				m.setStatus("profile saved: " + path)
			}
			return true, nil
		case "o":
			cfg := appState.GetScanConfig()
			path := strings.TrimSpace(cfg.ProfilePath)
			if path == "" {
				path = "gordian_profile.json"
			}
			if err := appState.LoadProfile(path); err != nil {
				m.setStatus("load failed: " + err.Error())
			} else {
				loaded := appState.GetScanConfig()
				if strings.TrimSpace(loaded.ProfilePath) == "" {
					loaded.ProfilePath = path
					appState.SetScanConfig(loaded)
				}
				m.SyncFromState(appState.GetScanConfig())
				m.setStatus("profile loaded: " + path)
			}
			return true, nil
		case "z":
			appState.ResetScanConfig()
			m.SyncFromState(appState.GetScanConfig())
			m.setStatus("config reset to defaults")
			return true, nil
		}
	}

	fields := m.Fields[m.ActiveMenu]
	visible := m.visibleFieldIndexes(m.ActiveMenu)
	if len(fields) == 0 {
		return false, nil
	}
	if len(visible) == 0 {
		switch key {
		case "up", "down", "k", "j", "enter":
			return true, nil
		}
		return false, nil
	}

	focusPos := indexOfInt(visible, m.FocusIndex)
	if focusPos < 0 {
		focusPos = 0
		m.FocusIndex = visible[0]
	}

	switch key {
	case "up", "k":
		if focusPos > 0 {
			focusPos--
			m.FocusIndex = visible[focusPos]
		}
		return true, nil
	case "down", "j":
		if focusPos < len(visible)-1 {
			focusPos++
			m.FocusIndex = visible[focusPos]
		}
		return true, nil
	case "left", "h":
		if m.cycleFocusedPreset(appState, -1) {
			return true, nil
		}
	case "right", "l":
		if m.cycleFocusedPreset(appState, 1) {
			return true, nil
		}
	case "enter":
		if !m.canEditFocusedField() {
			if def := m.currentFieldDef(); configFieldHasSelector(def) {
				if def.AllowCustom {
					m.setStatus(def.Label + ": use left/right, pick custom, then enter")
				} else {
					m.setStatus(def.Label + ": use left/right to choose")
				}
				return true, nil
			}
		}
		m.Editing = true
		m.focusCurrentInput()
		return true, nil
	}

	return false, nil
}

func (m *ConfigModel) SyncFromState(cfg state.ScanConfig) {
	m.CustomValues = map[string]string{}
	m.CustomSelected = map[string]bool{}
	for _, menu := range orderedConfigMenus {
		inputs := m.Inputs[menu]
		defs := m.Fields[menu]
		for i := range inputs {
			value := getScanConfigValue(cfg, defs[i].Key)
			inputs[i].SetValue(value)
			if defs[i].AllowCustom && !configFieldValueIsPreset(defs[i], value) {
				m.CustomValues[defs[i].Key] = strings.TrimSpace(value)
				m.CustomSelected[defs[i].Key] = true
			}
		}
		m.Inputs[menu] = inputs
	}
	m.Editing = false
	m.blurAllInputs()
}

func (m *ConfigModel) IsEditing() bool {
	return m.Editing
}

func (m *ConfigModel) setStatus(message string) {
	m.StatusMessage = message
	m.StatusUntil = time.Now().Add(4 * time.Second)
}

func (m *ConfigModel) focusCurrentInput() {
	m.blurAllInputs()
	inputs := m.Inputs[m.ActiveMenu]
	if len(inputs) == 0 {
		return
	}
	if m.FocusIndex < 0 {
		m.FocusIndex = 0
	}
	if m.FocusIndex >= len(inputs) {
		m.FocusIndex = len(inputs) - 1
	}
	inputs[m.FocusIndex].Focus()
	m.Inputs[m.ActiveMenu] = inputs
}

func (m *ConfigModel) blurAllInputs() {
	for _, menu := range orderedConfigMenus {
		inputs := m.Inputs[menu]
		for i := range inputs {
			inputs[i].Blur()
		}
		m.Inputs[menu] = inputs
	}
}

func (m *ConfigModel) syncFocusedValueToState(appState *state.AppState) {
	defs := m.Fields[m.ActiveMenu]
	inputs := m.Inputs[m.ActiveMenu]
	if len(defs) == 0 || len(inputs) == 0 {
		return
	}
	if m.FocusIndex < 0 || m.FocusIndex >= len(defs) {
		return
	}

	def := defs[m.FocusIndex]
	value := inputs[m.FocusIndex].Value()
	if def.AllowCustom {
		if m.CustomSelected[def.Key] || !configFieldValueIsPreset(def, value) {
			m.CustomSelected[def.Key] = true
			if trimmed := strings.TrimSpace(value); trimmed != "" {
				m.CustomValues[def.Key] = trimmed
			}
		} else if configFieldValueIsPreset(def, value) {
			m.CustomSelected[def.Key] = false
		}
	}

	cfg := appState.GetScanConfig()
	setScanConfigValue(&cfg, def.Key, value)
	appState.SetScanConfig(cfg)
}

func (m *ConfigModel) currentFieldDef() configField {
	defs := m.Fields[m.ActiveMenu]
	if m.FocusIndex < 0 || m.FocusIndex >= len(defs) {
		return configField{}
	}
	return defs[m.FocusIndex]
}

func (m *ConfigModel) canEditFocusedField() bool {
	def := m.currentFieldDef()
	if !configFieldHasSelector(def) {
		return true
	}
	if !def.AllowCustom {
		return false
	}
	return m.selectedPresetIndex(def, m.focusedFieldValue()) == len(def.Presets)
}

func (m *ConfigModel) focusedFieldValue() string {
	inputs := m.Inputs[m.ActiveMenu]
	if m.FocusIndex < 0 || m.FocusIndex >= len(inputs) {
		return ""
	}
	return inputs[m.FocusIndex].Value()
}

func (m *ConfigModel) cycleFocusedPreset(appState *state.AppState, delta int) bool {
	def := m.currentFieldDef()
	if !configFieldHasSelector(def) {
		return false
	}

	inputs := m.Inputs[m.ActiveMenu]
	if m.FocusIndex < 0 || m.FocusIndex >= len(inputs) {
		return false
	}

	current := inputs[m.FocusIndex].Value()
	total := len(def.Presets)
	if def.AllowCustom {
		total++
	}
	if total == 0 {
		return false
	}

	index := m.selectedPresetIndex(def, current)
	if index < 0 {
		index = 0
	}
	index = (index + delta + total) % total

	if index == len(def.Presets) && def.AllowCustom {
		m.CustomSelected[def.Key] = true
		custom := m.customValue(def, current)
		inputs[m.FocusIndex].SetValue(custom)
		m.Inputs[m.ActiveMenu] = inputs
		m.syncFocusedValueToState(appState)
		if custom == "" {
			m.setStatus(def.Label + ": custom")
		} else {
			m.setStatus(def.Label + ": custom ready")
		}
		return true
	}

	if def.AllowCustom && !configFieldValueIsPreset(def, current) {
		if trimmed := strings.TrimSpace(current); trimmed != "" {
			m.CustomValues[def.Key] = trimmed
		}
	}
	m.CustomSelected[def.Key] = false
	inputs[m.FocusIndex].SetValue(def.Presets[index].Value)
	m.Inputs[m.ActiveMenu] = inputs
	m.syncFocusedValueToState(appState)
	m.setStatus(def.Label + ": " + def.Presets[index].Label)
	return true
}

func (m *ConfigModel) syncViewport(focusPos int, maxRows int) {
	if maxRows < 1 {
		maxRows = 1
	}
	if focusPos < m.ScrollOffset {
		m.ScrollOffset = focusPos
	}
	if focusPos >= m.ScrollOffset+maxRows {
		m.ScrollOffset = focusPos - maxRows + 1
	}
	if m.ScrollOffset < 0 {
		m.ScrollOffset = 0
	}
}

func (m *ConfigModel) visibleFieldIndexes(menu ConfigMenu) []int {
	defs := m.Fields[menu]
	if len(defs) == 0 {
		return nil
	}
	indexes := make([]int, len(defs))
	for i := range defs {
		indexes[i] = i
	}
	return indexes
}

func indexOfInt(values []int, target int) int {
	for i, v := range values {
		if v == target {
			return i
		}
	}
	return -1
}

func firstFieldIndex(fields []configField) int {
	if len(fields) == 0 {
		return 0
	}
	return 0
}

func configFieldHasSelector(def configField) bool {
	return len(def.Presets) > 0
}

func normalizeConfigFieldValue(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func configFieldValueIsPreset(def configField, value string) bool {
	normalized := normalizeConfigFieldValue(value)
	for _, preset := range def.Presets {
		if normalizeConfigFieldValue(preset.Value) == normalized {
			return true
		}
	}
	return false
}

func (m *ConfigModel) selectedPresetIndex(def configField, value string) int {
	if def.AllowCustom && m.CustomSelected[def.Key] {
		return len(def.Presets)
	}

	normalized := normalizeConfigFieldValue(value)
	for i, preset := range def.Presets {
		if normalizeConfigFieldValue(preset.Value) == normalized {
			return i
		}
	}
	if def.AllowCustom {
		return len(def.Presets)
	}
	return -1
}

func (m *ConfigModel) customValue(def configField, value string) string {
	if !configFieldValueIsPreset(def, value) {
		return strings.TrimSpace(value)
	}
	return strings.TrimSpace(m.CustomValues[def.Key])
}

func (m *ConfigModel) renderFieldValue(def configField, value string, width int, focused bool) string {
	if configFieldHasSelector(def) {
		if focused {
			return m.renderPresetSummary(def, value, width)
		}
		return m.renderPresetValue(def, value, width)
	}

	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}
	return truncate(trimmed, width)
}

func (m *ConfigModel) renderPresetSummary(def configField, value string, width int) string {
	parts := make([]string, 0, len(def.Presets)+1)
	selected := m.selectedPresetIndex(def, value)
	for i, preset := range def.Presets {
		label := preset.Label
		if i == selected {
			label = "[" + label + "]"
		}
		parts = append(parts, label)
	}
	if def.AllowCustom {
		customLabel := "custom"
		if selected == len(def.Presets) {
			customLabel = "[" + customLabel + "]"
		}
		parts = append(parts, customLabel)
	}

	summary := strings.Join(parts, " | ")
	if def.AllowCustom && selected == len(def.Presets) {
		if custom := m.customValue(def, value); custom != "" {
			summary += " => " + custom
		}
	}
	return truncate(summary, width)
}

func (m *ConfigModel) renderPresetValue(def configField, value string, width int) string {
	selected := m.selectedPresetIndex(def, value)
	if selected >= 0 && selected < len(def.Presets) {
		return truncate(def.Presets[selected].Label, width)
	}
	if def.AllowCustom {
		custom := m.customValue(def, value)
		if custom == "" {
			return "custom"
		}
		return truncate("custom: "+custom, width)
	}
	return truncate(strings.TrimSpace(value), width)
}

func menuFromKey(key string) ConfigMenu {
	switch key {
	case "1":
		return MenuTargetMode
	case "2":
		return MenuRateLimits
	case "3":
		return MenuCVEPolicy
	case "4":
		return MenuBudget
	case "5":
		return MenuFlags
	case "6":
		return MenuProfiles
	default:
		return 0
	}
}

func configFieldLayout() map[ConfigMenu][]configField {
	return map[ConfigMenu][]configField{
		MenuTargetMode: {
			{Key: "target", Label: "target", Placeholder: "demo.testfire.net or 10.0.0.0/24"},
			{Key: "offensive_mode", Label: "offensive_mode", Placeholder: "pick a mode or custom", Presets: []configPreset{{Label: "auto", Value: "auto"}, {Label: "manual", Value: "manual"}, {Label: "dry-run", Value: "dry-run"}, {Label: "disabled", Value: "disabled"}}, AllowCustom: true},
			{Key: "offensive_speed", Label: "offensive_speed", Placeholder: "pick a speed or custom", Presets: []configPreset{{Label: "stealth", Value: "stealth"}, {Label: "balanced", Value: "balanced"}, {Label: "aggressive", Value: "aggressive"}}, AllowCustom: true},
			{Key: "offensive_intensity", Label: "offensive_intensity", Placeholder: "pick an intensity or custom", Presets: []configPreset{{Label: "low", Value: "low"}, {Label: "medium", Value: "medium"}, {Label: "high", Value: "high"}}, AllowCustom: true},
			{Key: "offensive_tools", Label: "offensive_tools", Placeholder: "csv override after choosing custom", Presets: []configPreset{{Label: "enabled-tools", Value: ""}}, AllowCustom: true},
			{Key: "network_file", Label: "network_file", Placeholder: "type custom topology path", Presets: []configPreset{{Label: "auto", Value: ""}}, AllowCustom: true},
			{Key: "cve_file", Label: "cve_file", Placeholder: "type custom cve feed path", Presets: []configPreset{{Label: "auto", Value: ""}}, AllowCustom: true},
		},
		MenuRateLimits: {
			{Key: "max_nmap_rate", Label: "max_nmap_rate", Placeholder: "int"},
			{Key: "max_ffuf_threads", Label: "max_ffuf_threads", Placeholder: "int"},
			{Key: "max_nuclei_rate", Label: "max_nuclei_rate", Placeholder: "int"},
			{Key: "wordlist_profile", Label: "wordlist_profile", Placeholder: "catalog profile key"},
			{Key: "ffuf_wordlist", Label: "ffuf_wordlist", Placeholder: "type custom wordlist path", Presets: []configPreset{{Label: "auto", Value: ""}}, AllowCustom: true},
		},
		MenuCVEPolicy: {
			{Key: "asset_aware_cves", Label: "asset_aware_cves", Placeholder: "true | false", Presets: []configPreset{{Label: "true", Value: "true"}, {Label: "false", Value: "false"}}},
			{Key: "asset_cve_min_score", Label: "asset_cve_min_score", Placeholder: "int"},
			{Key: "asset_cve_keep_top", Label: "asset_cve_keep_top", Placeholder: "int"},
		},
		MenuBudget: {
			{Key: "max_total_targets", Label: "max_total_targets", Placeholder: "int"},
			{Key: "max_total_commands", Label: "max_total_commands", Placeholder: "int"},
			{Key: "max_findings", Label: "max_findings", Placeholder: "int"},
			{Key: "max_run_seconds", Label: "max_run_seconds", Placeholder: "int"},
			{Key: "top_patches", Label: "top_patches", Placeholder: "int"},
		},
		MenuFlags: {
			{Key: "run_remediation", Label: "run_remediation", Placeholder: "true | false", Presets: []configPreset{{Label: "true", Value: "true"}, {Label: "false", Value: "false"}}},
			{Key: "bugbounty_mode", Label: "bugbounty_mode", Placeholder: "true | false | blank", Presets: []configPreset{{Label: "true", Value: "true"}, {Label: "false", Value: "false"}, {Label: "blank", Value: ""}}},
		},
		MenuProfiles: {
			{Key: "profile_path", Label: "profile_path", Placeholder: "gordian_profile.json"},
		},
	}
}

func getScanConfigValue(cfg state.ScanConfig, key string) string {
	switch key {
	case "target":
		return cfg.Target
	case "network_file":
		return cfg.NetworkFile
	case "cve_file":
		return cfg.CVEFile
	case "offensive_mode":
		return cfg.OffensiveMode
	case "offensive_speed":
		return cfg.OffensiveSpeed
	case "offensive_intensity":
		return cfg.OffensiveIntensity
	case "offensive_tools":
		return cfg.OffensiveTools
	case "max_nmap_rate":
		return cfg.MaxNmapRate
	case "max_ffuf_threads":
		return cfg.MaxFfufThreads
	case "max_nuclei_rate":
		return cfg.MaxNucleiRate
	case "max_total_targets":
		return cfg.MaxTotalTargets
	case "max_total_commands":
		return cfg.MaxTotalCommands
	case "max_findings":
		return cfg.MaxFindings
	case "max_run_seconds":
		return cfg.MaxRunSeconds
	case "wordlist_profile":
		return cfg.WordlistProfile
	case "ffuf_wordlist":
		return cfg.FfufWordlist
	case "run_remediation":
		return cfg.RunRemediation
	case "top_patches":
		return cfg.TopPatches
	case "asset_aware_cves":
		return cfg.AssetAwareCVEs
	case "asset_cve_min_score":
		return cfg.AssetCVEMinScore
	case "asset_cve_keep_top":
		return cfg.AssetCVEKeepTop
	case "bugbounty_mode":
		return cfg.BugbountyMode
	case "profile_path":
		return cfg.ProfilePath
	default:
		return ""
	}
}

func setScanConfigValue(cfg *state.ScanConfig, key, value string) {
	trimmed := strings.TrimSpace(value)
	switch key {
	case "target":
		cfg.Target = trimmed
	case "network_file":
		cfg.NetworkFile = trimmed
	case "cve_file":
		cfg.CVEFile = trimmed
	case "offensive_mode":
		cfg.OffensiveMode = trimmed
	case "offensive_speed":
		cfg.OffensiveSpeed = trimmed
	case "offensive_intensity":
		cfg.OffensiveIntensity = trimmed
	case "offensive_tools":
		cfg.OffensiveTools = trimmed
	case "max_nmap_rate":
		cfg.MaxNmapRate = trimmed
	case "max_ffuf_threads":
		cfg.MaxFfufThreads = trimmed
	case "max_nuclei_rate":
		cfg.MaxNucleiRate = trimmed
	case "max_total_targets":
		cfg.MaxTotalTargets = trimmed
	case "max_total_commands":
		cfg.MaxTotalCommands = trimmed
	case "max_findings":
		cfg.MaxFindings = trimmed
	case "max_run_seconds":
		cfg.MaxRunSeconds = trimmed
	case "wordlist_profile":
		cfg.WordlistProfile = trimmed
	case "ffuf_wordlist":
		cfg.FfufWordlist = trimmed
	case "run_remediation":
		cfg.RunRemediation = trimmed
	case "top_patches":
		cfg.TopPatches = trimmed
	case "asset_aware_cves":
		cfg.AssetAwareCVEs = trimmed
	case "asset_cve_min_score":
		cfg.AssetCVEMinScore = trimmed
	case "asset_cve_keep_top":
		cfg.AssetCVEKeepTop = trimmed
	case "bugbounty_mode":
		cfg.BugbountyMode = trimmed
	case "profile_path":
		cfg.ProfilePath = trimmed
	}
}

func renderConfigTabs(config *ConfigModel, width int) string {
	maxWidth := width - 2
	if maxWidth < 18 {
		maxWidth = 18
	}

	activeStyle := ToolSelectedStyle.Copy().Padding(0, 1)
	inactiveStyle := DimStyle.Copy().
		Foreground(ColorDimWhite).
		Background(lipgloss.Color("#001010")).
		Padding(0, 1)

	rows := make([]string, 0, 3)
	current := "  "
	currentWidth := 2

	for _, menu := range orderedConfigMenus {
		short := configMenuShortTitles[menu]
		if short == "" {
			short = configMenuTitles[menu]
		}
		raw := fmt.Sprintf("%d %s", menu, short)
		styled := inactiveStyle.Render(raw)
		if menu == config.ActiveMenu {
			styled = activeStyle.Render(raw)
		}

		piece := styled + " "
		pieceWidth := lipgloss.Width(piece)
		if currentWidth+pieceWidth > maxWidth && currentWidth > 2 {
			rows = append(rows, current)
			current = "  " + piece
			currentWidth = 2 + pieceWidth
			continue
		}

		current += piece
		currentWidth += pieceWidth
	}

	rows = append(rows, current)
	return strings.Join(rows, "\n")
}

func configMenuIcon(menu ConfigMenu) string {
	switch menu {
	case MenuTargetMode:
		return "◎"
	case MenuRateLimits:
		return "⇆"
	case MenuCVEPolicy:
		return "🛡"
	case MenuBudget:
		return "$"
	case MenuFlags:
		return "⚑"
	case MenuProfiles:
		return "💾"
	default:
		return "•"
	}
}

func configStatusStyle(message string) lipgloss.Style {
	msg := strings.ToLower(strings.TrimSpace(message))
	switch {
	case strings.Contains(msg, "failed") || strings.Contains(msg, "error"):
		return StatusError
	case strings.Contains(msg, "reset"):
		return StatusWarning
	case strings.Contains(msg, "filter"):
		return StatusRunning
	default:
		return StatusOK
	}
}

func renderConfigHints(menu ConfigMenu, width int) string {
	if width < 56 {
		return DimStyle.Render("  1-6 tabs  enter/custom  <- -> choose")
	}

	parts := []string{
		fmt.Sprintf("%s tabs", KeyStyle.Render("1-6")),
		fmt.Sprintf("%s select", KeyStyle.Render("↑↓")),
		fmt.Sprintf("%s choose", KeyStyle.Render("←→")),
		fmt.Sprintf("%s custom", KeyStyle.Render("enter")),
	}

	return "  " + strings.Join(parts, "  ")
}

func renderConfigSectionLine(title string, width int) string {
	dashCount := width - len(title) - 6
	if dashCount < 4 {
		dashCount = 4
	}
	return SubtitleStyle.Render(fmt.Sprintf("  %s %s", title, strings.Repeat("─", dashCount)))
}

// RenderConfigPanel renders the interactive command configuration sidebar.
func RenderConfigPanel(appState *state.AppState, config *ConfigModel, width, height int) string {
	var b strings.Builder

	w := width - 4
	h := height - 2
	if w < 1 {
		w = 1
	}
	if h < 1 {
		h = 1
	}

	defs := config.Fields[config.ActiveMenu]
	visible := config.visibleFieldIndexes(config.ActiveMenu)
	inputs := config.Inputs[config.ActiveMenu]

	headerBadge := DimStyle.Render(fmt.Sprintf("  [%d/%d]", len(visible), len(defs)))
	b.WriteString(PanelHeader.Render("⚙ COMMAND CONFIG" + headerBadge))
	b.WriteString("\n")
	b.WriteString("  " + HighlightStyle.Render(fmt.Sprintf("%s %s", configMenuIcon(config.ActiveMenu), configMenuTitles[config.ActiveMenu])))
	b.WriteString("\n")
	b.WriteString(renderConfigTabs(config, w))
	b.WriteString("\n")
	b.WriteString(renderConfigHints(config.ActiveMenu, w))
	b.WriteString("\n")

	b.WriteString(renderConfigSectionLine("FIELDS", w))
	b.WriteString("\n")

	if len(defs) > 0 && len(visible) > 0 {
		fieldRows := h - 13
		if config.ActiveMenu == MenuProfiles {
			fieldRows -= 2
		}
		if fieldRows < 1 {
			fieldRows = 1
		}

		focusPos := indexOfInt(visible, config.FocusIndex)
		if focusPos < 0 {
			focusPos = 0
			config.FocusIndex = visible[0]
		}
		config.syncViewport(focusPos, fieldRows)

		startPos := config.ScrollOffset
		endPos := startPos + fieldRows
		if endPos > len(visible) {
			endPos = len(visible)
		}

		for pos := startPos; pos < endPos; pos++ {
			i := visible[pos]
			fieldNo := fmt.Sprintf("%02d", i+1)
			label := defs[i].Label
			if len(label) > 17 {
				label = label[:17]
			}

			valueWidth := w - 30
			if valueWidth < 8 {
				valueWidth = 8
			}

			var valueText string
			if i == config.FocusIndex && config.Editing {
				inputs[i].Width = valueWidth
				valueText = inputs[i].View()
			} else {
				value := inputs[i].Value()
				renderedValue := config.renderFieldValue(defs[i], value, valueWidth, i == config.FocusIndex)
				if value == "" {
					if renderedValue != "" {
						valueText = BaseStyle.Render(renderedValue)
					} else if i == config.FocusIndex && defs[i].Placeholder != "" {
						valueText = DimStyle.Render("<" + truncate(defs[i].Placeholder, valueWidth-2) + ">")
					} else {
						valueText = DimStyle.Render("<empty>")
					}
				} else {
					valueText = BaseStyle.Render(renderedValue)
				}
			}

			line := fmt.Sprintf("  %s %-17s : %s", DimStyle.Render(fieldNo), label, valueText)
			if i == config.FocusIndex {
				prefix := "▸"
				if config.Editing {
					prefix = "✎"
				}
				line = ToolSelectedStyle.Width(w).Render(fmt.Sprintf(" %s %s %-17s : %s", prefix, fieldNo, label, valueText))
			}
			b.WriteString(line)
			b.WriteString("\n")
		}

		if startPos > 0 {
			b.WriteString(DimStyle.Render("  ↑ more fields"))
			b.WriteString("\n")
		}
		if endPos < len(visible) {
			b.WriteString(DimStyle.Render("  ↓ more fields"))
			b.WriteString("\n")
		}
	} else if len(defs) > 0 && len(visible) == 0 {
		b.WriteString("\n")
		b.WriteString(StatusWarning.Render("  no visible fields"))
		b.WriteString("\n")
	}

	if config.ActiveMenu == MenuProfiles {
		b.WriteString("\n")
		b.WriteString(fmt.Sprintf("  %s save  %s load  %s reset defaults",
			KeyStyle.Render("w"),
			KeyStyle.Render("o"),
			KeyStyle.Render("z"),
		))
		b.WriteString("\n")
	}

	if config.StatusMessage != "" {
		if time.Now().Before(config.StatusUntil) {
			statusStyle := configStatusStyle(config.StatusMessage)
			b.WriteString("\n")
			b.WriteString(statusStyle.Render("  " + truncate(config.StatusMessage, w-2)))
			b.WriteString("\n")
		} else {
			config.StatusMessage = ""
		}
	}

	b.WriteString("\n")
	b.WriteString(renderConfigSectionLine("STATE", w))
	b.WriteString("\n")
	b.WriteString(fmt.Sprintf("  %s %s   %s %s\n",
		DimStyle.Render("scan:"),
		renderScanStatus(appState.CurrentScan.Status),
		DimStyle.Render("ws:"),
		renderServerStatus(appState.ServerStatus),
	))

	if config.Editing {
		b.WriteString(fmt.Sprintf("  %s apply  %s stop editing",
			KeyStyle.Render("enter"),
			KeyStyle.Render("esc"),
		))
	} else {
		b.WriteString(fmt.Sprintf("  %s custom input  %s start scan",
			KeyStyle.Render("enter"),
			KeyStyle.Render("s"),
		))
	}
	b.WriteString("\n")

	content := truncateLines(b.String(), h)
	return PanelBorder.Width(w).Height(h).Render(content)
}

// ── Kill chain panel ────────────────────────────────────────────────

func RenderKillChains(chains []state.KillChain, width, height int) string {
	var b strings.Builder

	w := width - 4
	h := height - 2
	if w < 1 {
		w = 1
	}
	if h < 1 {
		h = 1
	}

	// Use danger style when chains exist
	borderStyle := PanelBorder
	headerStyle := PanelHeader
	if len(chains) > 0 {
		borderStyle = PanelBorderDanger
		headerStyle = PanelHeaderDanger
	}

	countStr := ""
	if len(chains) > 0 {
		countStr = fmt.Sprintf("  %s", StatusError.Render(fmt.Sprintf("⚠ %d PATHS", len(chains))))
	}
	b.WriteString(headerStyle.Render("☠ KILL CHAINS" + countStr))
	b.WriteString("\n")

	if len(chains) == 0 {
		b.WriteString("\n")
		b.WriteString(DimStyle.Render("  ○  No attack paths discovered"))
		b.WriteString("\n")
		b.WriteString(DimStyle.Render("     Network appears segmented"))

		content := truncateLines(b.String(), h)
		return borderStyle.Width(w).Height(h).Render(content)
	}

	maxShow := 5
	for i, chain := range chains {
		if i >= maxShow {
			b.WriteString(DimStyle.Render(fmt.Sprintf("  … and %d more paths\n", len(chains)-i)))
			break
		}

		// Risk coloring + icon
		riskStr := fmt.Sprintf("%.0f", chain.RiskScore)
		var riskStyled, riskIcon string
		switch {
		case chain.RiskScore >= 70:
			riskStyled = StatusError.Render(riskStr)
			riskIcon = GlitchStyle.Render("☠")
		case chain.RiskScore >= 40:
			riskStyled = StatusWarning.Render(riskStr)
			riskIcon = StatusWarning.Render("◆")
		default:
			riskStyled = StatusOK.Render(riskStr)
			riskIcon = StatusOK.Render("◇")
		}

		// Header line
		target := HighlightStyle.Render(truncate(chain.TargetHostname, 18))
		hopsStr := DimStyle.Render(fmt.Sprintf("%d hops", chain.Hops))
		b.WriteString(fmt.Sprintf("  %s #%d %s  risk:%s  %s\n",
			riskIcon, i+1, target, riskStyled, hopsStr))

		// Exploit chain preview
		if len(chain.ExploitChain) > 0 {
			sep := SubtitleStyle.Render("▸")
			chainStr := strings.Join(chain.ExploitChain, " "+sep+" ")
			maxLen := w - 6
			if lipgloss.Width(chainStr) > maxLen && maxLen > 8 {
				chainStr = lipgloss.NewStyle().
					Foreground(lipgloss.Color("#666666")).
					Background(ColorBg).
					Render(truncate(strings.Join(chain.ExploitChain, "▸"), maxLen))
			} else {
				chainStr = StatusWarning.Render(chainStr)
			}
			b.WriteString(fmt.Sprintf("    %s\n", chainStr))
		}
	}

	content := truncateLines(b.String(), h)
	return borderStyle.Width(w).Height(h).Render(content)
}

// ── Helpers ─────────────────────────────────────────────────────────

func renderServerStatus(status string) string {
	switch status {
	case "online":
		return StatusOK.Render("● online")
	case "connecting":
		return StatusWarning.Render("◌ connecting…")
	default:
		return StatusError.Render("✖ offline")
	}
}

func renderScanStatus(status string) string {
	switch status {
	case "running":
		return StatusRunning.Render("▶ running")
	case "completed":
		return StatusOK.Render("✔ completed")
	case "failed":
		return StatusError.Render("✖ failed")
	default:
		return DimStyle.Render("○ idle")
	}
}

func renderDangerCount(n int) string {
	s := fmt.Sprintf("%d", n)
	if n > 0 {
		return FindingStyle.Render(s)
	}
	return DimStyle.Render(s)
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max <= 1 {
		return "…"
	}
	return s[:max-1] + "…"
}
