/*
Package state manages all internal TUI state — scan data, tool status,
WebSocket events, and user preferences.
*/
package state

import (
	"sync"
	"time"
)

// ── Scan Status ─────────────────────────────────────────────────────

type ScanStatus string

const (
	StatusIdle      ScanStatus = "idle"
	StatusRunning   ScanStatus = "running"
	StatusCompleted ScanStatus = "completed"
	StatusFailed    ScanStatus = "failed"
)

// ── Tool Definition ─────────────────────────────────────────────────

type Tool struct {
	Name        string
	Icon        string
	Description string
	Enabled     bool
	Running     bool
	Category    string // recon, scan, exploit, util
}

// ── Finding (offensive tool result) ─────────────────────────────────

type Finding struct {
	Tool       string                 `json:"tool"`
	Type       string                 `json:"type"`
	Technical  string                 `json:"technical"`
	Narrative  string                 `json:"narrative"`
	Confidence float64                `json:"confidence"`
	Severity   string                 `json:"severity"`
	Target     string                 `json:"target"`
	Metadata   map[string]interface{} `json:"metadata"`
}

// ── OffensiveImpact (baseline vs post-offensive delta) ──────────────

type OffensiveImpact struct {
	BaselineChains int      `json:"baseline_chains"`
	PostChains     int      `json:"post_chains"`
	NewChains      int      `json:"new_chains"`
	NewTargetHosts []string `json:"new_target_hosts"`
	EdgesAdded     int      `json:"edges_added"`
	HostsAdded     int      `json:"hosts_added"`
}

// ── Live Event from WebSocket ───────────────────────────────────────

type LiveEvent struct {
	Type      string                 `json:"type"`
	Timestamp string                 `json:"timestamp"`
	Tool      string                 `json:"tool"`
	Level     string                 `json:"level"`
	Message   string                 `json:"message"`
	Payload   map[string]interface{} `json:"payload"`
	Sequence  int                    `json:"sequence"`
	ScanID    string                 `json:"scan_id"`
}

// ── Scan Info ───────────────────────────────────────────────────────

type ScanInfo struct {
	ScanID          string  `json:"scan_id"`
	Status          string  `json:"status"`
	Stage           string  `json:"stage"`
	ProgressPercent float64 `json:"progress_percent"`
	Message         string  `json:"message"`
	ElapsedSeconds  float64 `json:"elapsed_seconds"`
	Hosts           int     `json:"hosts"`
	Edges           int     `json:"edges"`
	KillChains      int     `json:"kill_chains"`
	Findings        int     `json:"findings"`
	Patches         int     `json:"patches"`
}

// ── Scan Configuration ──────────────────────────────────────────────

type ScanConfig struct {
	Target             string `json:"target"`
	NetworkFile        string `json:"network_file"`
	CVEFile            string `json:"cve_file"`
	OutputDir          string `json:"output_dir"`
	OffensiveMode      string `json:"offensive_mode"`
	OffensiveSpeed     string `json:"offensive_speed"`
	OffensiveIntensity string `json:"offensive_intensity"`
	OffensiveTools     string `json:"offensive_tools"`

	NmapBin      string `json:"nmap_bin"`
	FfufBin      string `json:"ffuf_bin"`
	NucleiBin    string `json:"nuclei_bin"`
	SubfinderBin string `json:"subfinder_bin"`
	HttpxBin     string `json:"httpx_bin"`
	KatanaBin    string `json:"katana_bin"`
	GitleaksBin  string `json:"gitleaks_bin"`
	GowitnessBin string `json:"gowitness_bin"`

	NmapExtraArgs      string `json:"nmap_extra_args"`
	FfufExtraArgs      string `json:"ffuf_extra_args"`
	NucleiExtraArgs    string `json:"nuclei_extra_args"`
	SubfinderExtraArgs string `json:"subfinder_extra_args"`
	HttpxExtraArgs     string `json:"httpx_extra_args"`
	KatanaExtraArgs    string `json:"katana_extra_args"`
	GitleaksExtraArgs  string `json:"gitleaks_extra_args"`
	GowitnessExtraArgs string `json:"gowitness_extra_args"`

	NmapCommand      string `json:"nmap_command"`
	FfufCommand      string `json:"ffuf_command"`
	NucleiCommand    string `json:"nuclei_command"`
	SubfinderCommand string `json:"subfinder_command"`
	HttpxCommand     string `json:"httpx_command"`
	KatanaCommand    string `json:"katana_command"`
	GitleaksCommand  string `json:"gitleaks_command"`
	GowitnessCommand string `json:"gowitness_command"`

	MaxNmapRate      string `json:"max_nmap_rate"`
	MaxFfufThreads   string `json:"max_ffuf_threads"`
	MaxNucleiRate    string `json:"max_nuclei_rate"`
	MaxTotalTargets  string `json:"max_total_targets"`
	MaxTotalCommands string `json:"max_total_commands"`
	MaxFindings      string `json:"max_findings"`
	MaxRunSeconds    string `json:"max_run_seconds"`

	WordlistProfile string `json:"wordlist_profile"`
	FfufWordlist    string `json:"ffuf_wordlist"`
	CVEProfile      string `json:"cve_profile"`
	CVEAutoDownload string `json:"cve_auto_download"`
	CVESyncPolicy   string `json:"cve_sync_policy"`

	RunRemediation   string `json:"run_remediation"`
	TopPatches       string `json:"top_patches"`
	AssetAwareCVEs   string `json:"asset_aware_cves"`
	AssetCVEMinScore string `json:"asset_cve_min_score"`
	AssetCVEKeepTop  string `json:"asset_cve_keep_top"`
	BugbountyMode    string `json:"bugbounty_mode"`
	FullControl      string `json:"full_control"`

	ProfilePath string `json:"profile_path"`
}

// ── Graph Data ──────────────────────────────────────────────────────

type HostNode struct {
	ID              string `json:"id"`
	Hostname        string `json:"hostname"`
	IPAddress       string `json:"ip_address"`
	Segment         string `json:"segment"`
	OS              string `json:"os"`
	IsAttackerEntry bool   `json:"is_attacker_entry"`
	IsCrownJewel    bool   `json:"is_crown_jewel"`
}

type GraphEdge struct {
	Source   string  `json:"source"`
	Target   string  `json:"target"`
	Port     int     `json:"port"`
	CVEID    string  `json:"cve_id"`
	Cost     float64 `json:"cost"`
	CVSS     float64 `json:"cvss"`
	Category string  `json:"category"`
}

// ── Kill Chain ──────────────────────────────────────────────────────

type KillChain struct {
	TargetHostname string   `json:"target_hostname"`
	RiskScore      float64  `json:"risk_score"`
	Hops           int      `json:"hops"`
	ExploitChain   []string `json:"exploit_chain"`
}

// ── GeoMarker (world map) ───────────────────────────────────────────

type GeoMarker struct {
	Label      string
	Hostname   string
	IP         string
	RiskScore  int
	Latitude   float64
	Longitude  float64
	MarkerType string // target, nmap, overlap
	Active     bool
}

// ── AppState — thread-safe central state ────────────────────────────

type AppState struct {
	mu sync.RWMutex

	// Connection
	APIBaseURL    string
	WSConnected   bool
	StorageMode   string // "ram" or "sqlite"
	MaxConcurrent int

	// Scan
	CurrentScan ScanInfo
	ScanHistory []ScanInfo
	ScanConfig  ScanConfig

	// Graph
	Hosts       []HostNode
	Edges       []GraphEdge
	KillChains  []KillChain
	EntryPoints []string
	CrownJewels []string

	// Events
	Events    []LiveEvent
	MaxEvents int

	// Findings (live from offensive tools)
	Findings    []Finding
	MaxFindings int

	// Offensive impact (baseline vs post-run delta)
	Impact OffensiveImpact

	// Tools
	Tools []Tool

	// Geo
	GeoMarkers []GeoMarker

	// UI
	ActiveView   string // "dashboard", "map", "config", "toolbox"
	ActivePanel  int
	GlitchActive bool
	GlitchUntil  time.Time

	// Server info
	ServerVersion string
	ServerStatus  string

	// Error tracking
	LastError     string
	LastErrorTime time.Time
}

func NewAppState(apiBase string) *AppState {
	return &AppState{
		APIBaseURL:    apiBase,
		StorageMode:   "ram",
		MaxConcurrent: 1,
		MaxEvents:     500,
		MaxFindings:   200,
		ActiveView:    "dashboard",
		ServerVersion: "?",
		ServerStatus:  "connecting",
		CurrentScan: ScanInfo{
			Status: "idle",
			Stage:  "idle",
		},
		ScanConfig: defaultScanConfig(),
		Tools:      defaultTools(),
	}
}

func defaultScanConfig() ScanConfig {
	return ScanConfig{
		OffensiveMode:    "auto",
		CVEProfile:       "local",
		CVEAutoDownload:  "false",
		CVESyncPolicy:    "never",
		RunRemediation:   "true",
		TopPatches:       "5",
		AssetAwareCVEs:   "false",
		AssetCVEMinScore: "2",
		AssetCVEKeepTop:  "120",
		ProfilePath:      "gordian_profile.json",
	}
}

func defaultTools() []Tool {
	return []Tool{
		{Name: "nmap", Icon: "🔍", Description: "Network scanner & port discovery", Enabled: true, Category: "scan"},
		{Name: "ffuf", Icon: "📂", Description: "Web fuzzer & directory brute-force", Enabled: true, Category: "scan"},
		{Name: "nuclei", Icon: "☢", Description: "Vulnerability scanner with templates", Enabled: true, Category: "scan"},
		{Name: "subfinder", Icon: "🌐", Description: "Subdomain discovery", Enabled: false, Category: "recon"},
		{Name: "httpx", Icon: "🔗", Description: "HTTP probe & tech detect", Enabled: false, Category: "recon"},
		{Name: "katana", Icon: "🕷", Description: "Web crawler", Enabled: false, Category: "recon"},
		{Name: "gitleaks", Icon: "🔑", Description: "Secret detection in repos", Enabled: false, Category: "util"},
		{Name: "gowitness", Icon: "📸", Description: "Screenshot capture", Enabled: false, Category: "util"},
	}
}

// ── Thread-safe accessors ───────────────────────────────────────────

func (s *AppState) PushEvent(ev LiveEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Events = append(s.Events, ev)
	if len(s.Events) > s.MaxEvents {
		s.Events = s.Events[len(s.Events)-s.MaxEvents:]
	}
}

func (s *AppState) GetEvents(n int) []LiveEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if n <= 0 || n > len(s.Events) {
		n = len(s.Events)
	}
	start := len(s.Events) - n
	if start < 0 {
		start = 0
	}
	result := make([]LiveEvent, len(s.Events[start:]))
	copy(result, s.Events[start:])
	return result
}

func (s *AppState) SetScanInfo(info ScanInfo) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.CurrentScan = info
}

func (s *AppState) TriggerGlitch(duration time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.GlitchActive = true
	s.GlitchUntil = time.Now().Add(duration)
}

func (s *AppState) IsGlitchActive() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.GlitchActive {
		return false
	}
	if time.Now().After(s.GlitchUntil) {
		s.GlitchActive = false
		return false
	}
	return true
}

func (s *AppState) SetWSConnected(v bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.WSConnected = v
}

func (s *AppState) SetLastError(err string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.LastError = err
	s.LastErrorTime = time.Now()
}

func (s *AppState) GetLastError() (string, time.Time) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.LastError, s.LastErrorTime
}

func (s *AppState) ClearError() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.LastError = ""
}

func (s *AppState) GetScanConfig() ScanConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.ScanConfig
}

func (s *AppState) SetScanConfig(cfg ScanConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ScanConfig = cfg
}

func (s *AppState) ResetScanConfig() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ScanConfig = defaultScanConfig()
}

func (s *AppState) IsWSConnected() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.WSConnected
}

// PushFinding appends a finding to the live list, capping at MaxFindings.
// Drops the oldest when the cap is reached so the live panel always shows
// the most recent activity.
func (s *AppState) PushFinding(f Finding) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Findings = append(s.Findings, f)
	if s.MaxFindings > 0 && len(s.Findings) > s.MaxFindings {
		s.Findings = s.Findings[len(s.Findings)-s.MaxFindings:]
	}
}

// GetFindings returns up to n most recent findings (n<=0 returns all).
func (s *AppState) GetFindings(n int) []Finding {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if n <= 0 || n > len(s.Findings) {
		n = len(s.Findings)
	}
	start := len(s.Findings) - n
	if start < 0 {
		start = 0
	}
	out := make([]Finding, len(s.Findings[start:]))
	copy(out, s.Findings[start:])
	return out
}

// ReplaceFindings is used by REST polling to seed the panel with backend
// state on startup or reconnect, without dropping fresh WS deltas.
func (s *AppState) ReplaceFindings(items []Finding) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Findings = append([]Finding(nil), items...)
	if s.MaxFindings > 0 && len(s.Findings) > s.MaxFindings {
		s.Findings = s.Findings[len(s.Findings)-s.MaxFindings:]
	}
}

// SetToolRunning flips a tool's runtime flag based on offensive.tool_start /
// offensive.tool_done WS events. Unknown tools are ignored (no-op) so the
// state stays clean when the backend adds new tools we don't render yet.
func (s *AppState) SetToolRunning(tool string, running bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.Tools {
		if s.Tools[i].Name == tool {
			s.Tools[i].Running = running
			return
		}
	}
}

// SetImpact stores the latest OffensiveImpact (baseline vs post-offensive
// kill chain delta). Threat overview reads this to surface "+N new chains
// from offensive run".
func (s *AppState) SetImpact(impact OffensiveImpact) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Impact = impact
}

// GetImpact returns a copy of the current OffensiveImpact snapshot.
func (s *AppState) GetImpact() OffensiveImpact {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Impact
}
