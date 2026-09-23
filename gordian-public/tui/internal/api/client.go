/*
Package api provides a REST client for the Gordian Python backend.
All calls are synchronous and designed to be invoked from Bubble Tea Cmds.
*/
package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

type Client struct {
	BaseURL    string
	HTTPClient *http.Client
}

func NewClient(baseURL string) *Client {
	return &Client{
		BaseURL: baseURL,
		HTTPClient: &http.Client{
			Timeout:       30 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

// ── Server Info ─────────────────────────────────────────────────────

type ServerInfo struct {
	Name           string `json:"name"`
	Version        string `json:"version"`
	Status         string `json:"status"`
	StorageBackend string `json:"storage_backend"`
	MaxConcurrent  int    `json:"max_concurrent_scans"`
	ActiveScans    int    `json:"active_scans"`
	APIVersion     string `json:"api_version"`
}

func (c *Client) GetInfo() (ServerInfo, error) {
	var info ServerInfo
	err := c.getJSON("/api/v1/info", &info)
	return info, err
}

// ── Scan ────────────────────────────────────────────────────────────

type ScanStartRequest struct {
	Target             string   `json:"target,omitempty"`
	NetworkFile        string   `json:"network_file,omitempty"`
	CVEFile            string   `json:"cve_file,omitempty"`
	OutputDir          string   `json:"output_dir,omitempty"`
	OffensiveMode      string   `json:"offensive_mode,omitempty"`
	OffensiveSpeed     string   `json:"offensive_speed,omitempty"`
	OffensiveIntensity string   `json:"offensive_intensity,omitempty"`
	OffensiveTools     []string `json:"offensive_tools,omitempty"`

	CVEProfile      *string `json:"cve_profile,omitempty"`
	CVEAutoDownload *bool   `json:"cve_auto_download,omitempty"`
	CVESyncPolicy   *string `json:"cve_sync_policy,omitempty"`

	// Tool Overrides
	ToolBin       map[string]string   `json:"tool_bin,omitempty"`
	ToolExtraArgs map[string][]string `json:"tool_extra_args,omitempty"`
	ToolCommand   map[string][]string `json:"tool_command,omitempty"`

	// Rate limits / budget
	MaxNmapRate      *int `json:"max_nmap_rate,omitempty"`
	MaxFfufThreads   *int `json:"max_ffuf_threads,omitempty"`
	MaxNucleiRate    *int `json:"max_nuclei_rate,omitempty"`
	MaxTotalTargets  *int `json:"max_total_targets,omitempty"`
	MaxTotalCommands *int `json:"max_total_commands,omitempty"`
	MaxFindings      *int `json:"max_findings,omitempty"`
	MaxRunSeconds    *int `json:"max_run_seconds,omitempty"`

	// Wordlists
	WordlistProfile *string `json:"wordlist_profile,omitempty"`
	FfufWordlist    *string `json:"ffuf_wordlist,omitempty"`

	RunRemediation   bool  `json:"run_remediation"`
	TopPatches       int   `json:"top_patches"`
	AssetAwareCVEs   bool  `json:"asset_aware_cves"`
	AssetCVEMinScore int   `json:"asset_cve_min_score"`
	AssetCVEKeepTop  int   `json:"asset_cve_keep_top"`
	BugbountyMode    *bool `json:"bugbounty_mode,omitempty"`
	FullControl      *bool `json:"full_control,omitempty"`
}

type ScanStartResponse struct {
	ScanID  string `json:"scan_id"`
	Status  string `json:"status"`
	Message string `json:"message"`
}

func (c *Client) StartScan(req ScanStartRequest) (ScanStartResponse, error) {
	var resp ScanStartResponse
	err := c.postJSON("/api/v1/scan/start", req, &resp)
	return resp, err
}

type ScanCancelResponse struct {
	ScanID    string `json:"scan_id"`
	Cancelled bool   `json:"cancelled"`
}

func (c *Client) CancelScan(scanID string) (ScanCancelResponse, error) {
	var resp ScanCancelResponse
	if scanID == "" {
		return resp, fmt.Errorf("scan id required")
	}
	err := c.postJSON("/api/v1/scan/"+scanID+"/cancel", struct{}{}, &resp)
	return resp, err
}

type ScanStatusResponse struct {
	ScanID   string `json:"scan_id"`
	Status   string `json:"status"`
	Progress struct {
		Stage   string  `json:"stage"`
		Percent float64 `json:"percent"`
		Message string  `json:"message"`
	} `json:"progress"`
	Stats struct {
		Hosts      int `json:"hosts"`
		Edges      int `json:"edges"`
		KillChains int `json:"kill_chains"`
		Findings   int `json:"findings"`
		Patches    int `json:"patches"`
	} `json:"stats"`
	ElapsedSeconds float64 `json:"elapsed_seconds"`
	Error          *string `json:"error"`
}

func (c *Client) GetScanStatus(scanID string) (ScanStatusResponse, error) {
	var resp ScanStatusResponse
	url := "/api/v1/scan/status"
	if scanID != "" {
		url += "?scan_id=" + scanID
	}
	err := c.getJSON(url, &resp)
	return resp, err
}

type ScanListItem struct {
	ScanID          string  `json:"scan_id"`
	Status          string  `json:"status"`
	Stage           string  `json:"stage"`
	ProgressPercent float64 `json:"progress_percent"`
	ElapsedSeconds  float64 `json:"elapsed_seconds"`
	CreatedAt       string  `json:"created_at"`
	Error           *string `json:"error"`
}

func (c *Client) ListScans() ([]ScanListItem, error) {
	var items []ScanListItem
	err := c.getJSON("/api/v1/scan/list", &items)
	return items, err
}

// ── Graph ───────────────────────────────────────────────────────────

type GraphResponse struct {
	Hosts       []HostNode  `json:"hosts"`
	Edges       []GraphEdge `json:"edges"`
	EntryPoints []string    `json:"entry_points"`
	CrownJewels []string    `json:"crown_jewels"`
	NodeCount   int         `json:"node_count"`
	EdgeCount   int         `json:"edge_count"`
}

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

func (c *Client) GetGraph(scanID string) (GraphResponse, error) {
	var resp GraphResponse
	url := "/api/v1/graph"
	if scanID != "" {
		url += "?scan_id=" + scanID
	}
	err := c.getJSON(url, &resp)
	return resp, err
}

// ── Kill Chains ─────────────────────────────────────────────────────

type KillChainResponse struct {
	TargetHostname string   `json:"target_hostname"`
	RiskScore      float64  `json:"risk_score"`
	Hops           int      `json:"hops"`
	ExploitChain   []string `json:"exploit_chain"`
	TotalCost      float64  `json:"total_cost"`
	MaxCVSS        float64  `json:"max_cvss"`
}

func (c *Client) GetKillChains(scanID string) ([]KillChainResponse, error) {
	var chains []KillChainResponse
	url := "/api/v1/kill-chains"
	if scanID != "" {
		url += "?scan_id=" + scanID
	}
	err := c.getJSON(url, &chains)
	return chains, err
}

// ── Findings ────────────────────────────────────────────────────────

type FindingsResponse struct {
	Total        int           `json:"total"`
	Deduplicated int           `json:"deduplicated"`
	Findings     []FindingItem `json:"findings"`
}

type FindingItem struct {
	Tool       string                 `json:"tool"`
	Type       string                 `json:"type"`
	Technical  string                 `json:"technical"`
	Narrative  string                 `json:"narrative"`
	Confidence float64                `json:"confidence"`
	Severity   string                 `json:"severity"`
	Target     string                 `json:"target"`
	Metadata   map[string]interface{} `json:"metadata"`
}

func (c *Client) GetFindings(scanID string) (FindingsResponse, error) {
	var resp FindingsResponse
	url := "/api/v1/findings"
	if scanID != "" {
		url += "?scan_id=" + scanID
	}
	err := c.getJSON(url, &resp)
	return resp, err
}

// ── HTTP helpers ────────────────────────────────────────────────────

func (c *Client) getJSON(path string, target interface{}) error {
	req, err := http.NewRequest(http.MethodGet, c.BaseURL+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-API-Key", os.Getenv("GORDIAN_API_KEY"))
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("GET %s: %w", path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		return fmt.Errorf("GET %s: status %d: %s", path, resp.StatusCode, string(body))
	}

	return json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(target)
}

func (c *Client) postJSON(path string, body interface{}, target interface{}) error {
	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, c.BaseURL+path, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", os.Getenv("GORDIAN_API_KEY"))
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("POST %s: %w", path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		return fmt.Errorf("POST %s: status %d: %s", path, resp.StatusCode, string(respBody))
	}

	return json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(target)
}
