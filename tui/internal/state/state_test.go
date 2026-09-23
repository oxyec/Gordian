package state

import (
	"sync"
	"testing"
	"time"
)

func TestNewAppStateDefaults(t *testing.T) {
	s := NewAppState("http://localhost:8000")
	if s.APIBaseURL != "http://localhost:8000" {
		t.Errorf("APIBaseURL = %q, want http://localhost:8000", s.APIBaseURL)
	}
	if s.MaxEvents != 500 {
		t.Errorf("MaxEvents = %d, want 500", s.MaxEvents)
	}
	if s.CurrentScan.Status != "idle" {
		t.Errorf("CurrentScan.Status = %q, want idle", s.CurrentScan.Status)
	}
	if len(s.Tools) == 0 {
		t.Error("Tools should be populated with defaults")
	}
	if s.ScanConfig.OffensiveMode != "auto" {
		t.Errorf("ScanConfig.OffensiveMode = %q, want auto", s.ScanConfig.OffensiveMode)
	}
}

func TestPushEventRespectsMaxEvents(t *testing.T) {
	s := NewAppState("")
	s.MaxEvents = 3
	for i := 0; i < 10; i++ {
		s.PushEvent(LiveEvent{Sequence: i})
	}
	if got := len(s.Events); got != 3 {
		t.Fatalf("Events len = %d, want 3", got)
	}
	// Should retain the newest 3 (7, 8, 9).
	if s.Events[0].Sequence != 7 || s.Events[2].Sequence != 9 {
		t.Errorf("Events did not retain newest: got %+v", s.Events)
	}
}

func TestGetEventsLimit(t *testing.T) {
	s := NewAppState("")
	for i := 0; i < 5; i++ {
		s.PushEvent(LiveEvent{Sequence: i})
	}
	got := s.GetEvents(2)
	if len(got) != 2 {
		t.Fatalf("GetEvents(2) len = %d, want 2", len(got))
	}
	if got[0].Sequence != 3 || got[1].Sequence != 4 {
		t.Errorf("GetEvents(2) returned wrong slice: %+v", got)
	}
	// Asking for more than exists returns all.
	if all := s.GetEvents(100); len(all) != 5 {
		t.Errorf("GetEvents(100) len = %d, want 5", len(all))
	}
}

func TestGlitchExpiresAutomatically(t *testing.T) {
	s := NewAppState("")
	s.TriggerGlitch(20 * time.Millisecond)
	if !s.IsGlitchActive() {
		t.Fatal("glitch should be active immediately after Trigger")
	}
	time.Sleep(40 * time.Millisecond)
	if s.IsGlitchActive() {
		t.Error("glitch should auto-expire after duration")
	}
}

func TestSetAndClearError(t *testing.T) {
	s := NewAppState("")
	s.SetLastError("boom")
	msg, ts := s.GetLastError()
	if msg != "boom" {
		t.Errorf("LastError = %q, want boom", msg)
	}
	if ts.IsZero() {
		t.Error("LastErrorTime should be set")
	}
	s.ClearError()
	if msg, _ := s.GetLastError(); msg != "" {
		t.Errorf("after Clear, LastError = %q, want empty", msg)
	}
}

func TestWSConnectedToggle(t *testing.T) {
	s := NewAppState("")
	if s.IsWSConnected() {
		t.Error("initial WSConnected should be false")
	}
	s.SetWSConnected(true)
	if !s.IsWSConnected() {
		t.Error("after SetWSConnected(true), IsWSConnected should return true")
	}
}

func TestScanConfigResetRestoresDefaults(t *testing.T) {
	s := NewAppState("")
	cfg := s.GetScanConfig()
	cfg.Target = "evil.com"
	cfg.OffensiveMode = "manual"
	s.SetScanConfig(cfg)
	if s.GetScanConfig().Target != "evil.com" {
		t.Fatal("SetScanConfig did not stick")
	}
	s.ResetScanConfig()
	got := s.GetScanConfig()
	if got.Target != "" {
		t.Errorf("after Reset, Target = %q, want empty", got.Target)
	}
	if got.OffensiveMode != "auto" {
		t.Errorf("after Reset, OffensiveMode = %q, want auto", got.OffensiveMode)
	}
}

func TestPushFindingRespectsCap(t *testing.T) {
	s := NewAppState("")
	s.MaxFindings = 3
	for i := 0; i < 10; i++ {
		s.PushFinding(Finding{Tool: "nuclei", Technical: "cve"})
	}
	if got := len(s.Findings); got != 3 {
		t.Fatalf("Findings len = %d, want 3", got)
	}
}

func TestGetFindingsLimitsAndCopies(t *testing.T) {
	s := NewAppState("")
	for i := 0; i < 5; i++ {
		s.PushFinding(Finding{Tool: "t", Confidence: float64(i)})
	}
	out := s.GetFindings(2)
	if len(out) != 2 {
		t.Fatalf("GetFindings(2) len = %d", len(out))
	}
	if out[0].Confidence != 3 || out[1].Confidence != 4 {
		t.Errorf("returned wrong slice: %+v", out)
	}
	// Mutating the returned slice should not affect internal state.
	out[0].Tool = "MUTATED"
	if s.Findings[3].Tool == "MUTATED" {
		t.Error("GetFindings must return an independent copy")
	}
}

func TestReplaceFindingsSeedsList(t *testing.T) {
	s := NewAppState("")
	s.PushFinding(Finding{Tool: "stale"})
	s.ReplaceFindings([]Finding{{Tool: "fresh"}, {Tool: "newer"}})
	if len(s.Findings) != 2 || s.Findings[0].Tool != "fresh" {
		t.Errorf("ReplaceFindings did not seed correctly: %+v", s.Findings)
	}
}

func TestSetToolRunningUpdatesNamedToolOnly(t *testing.T) {
	s := NewAppState("")
	s.SetToolRunning("nuclei", true)
	for _, tool := range s.Tools {
		if tool.Name == "nuclei" && !tool.Running {
			t.Error("nuclei should be Running=true")
		}
		if tool.Name != "nuclei" && tool.Running {
			t.Errorf("%s wrongly flipped to Running", tool.Name)
		}
	}
	s.SetToolRunning("nuclei", false)
	for _, tool := range s.Tools {
		if tool.Name == "nuclei" && tool.Running {
			t.Error("nuclei should be Running=false after toggle")
		}
	}
}

func TestSetToolRunningIgnoresUnknownTool(t *testing.T) {
	s := NewAppState("")
	// Should not panic / add a phantom entry.
	s.SetToolRunning("brand-new-tool", true)
	for _, tool := range s.Tools {
		if tool.Name == "brand-new-tool" {
			t.Fatal("unknown tool should not be added")
		}
	}
}

func TestSetAndGetImpactRoundTrip(t *testing.T) {
	s := NewAppState("")
	imp := OffensiveImpact{
		BaselineChains: 3, PostChains: 7, NewChains: 4,
		EdgesAdded: 12, HostsAdded: 2,
		NewTargetHosts: []string{"a.example.com", "b.example.com"},
	}
	s.SetImpact(imp)
	got := s.GetImpact()
	if got.NewChains != 4 || got.PostChains != 7 || len(got.NewTargetHosts) != 2 {
		t.Errorf("GetImpact returned %+v, want %+v", got, imp)
	}
}

func TestSaveAndLoadProfileRoundTrip(t *testing.T) {
	tmp := t.TempDir() + "/profile.json"

	a := NewAppState("")
	cfg := a.GetScanConfig()
	cfg.Target = "evil.example.com"
	cfg.OffensiveMode = "manual"
	cfg.MaxNmapRate = "750"
	a.SetScanConfig(cfg)

	if err := a.SaveProfile(tmp); err != nil {
		t.Fatalf("SaveProfile: %v", err)
	}

	b := NewAppState("")
	if err := b.LoadProfile(tmp); err != nil {
		t.Fatalf("LoadProfile: %v", err)
	}
	got := b.GetScanConfig()
	if got.Target != "evil.example.com" || got.OffensiveMode != "manual" || got.MaxNmapRate != "750" {
		t.Errorf("LoadProfile did not restore values: %+v", got)
	}
	// Untouched fields should keep their default.
	if got.CVEProfile != "local" {
		t.Errorf("default CVEProfile lost after round-trip: %q", got.CVEProfile)
	}
}

func TestLoadProfileMissingFileReturnsError(t *testing.T) {
	a := NewAppState("")
	err := a.LoadProfile(t.TempDir() + "/does-not-exist.json")
	if err == nil {
		t.Fatal("expected error for missing profile file")
	}
}

func TestPushEventConcurrentSafe(t *testing.T) {
	s := NewAppState("")
	s.MaxEvents = 1000
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				s.PushEvent(LiveEvent{Sequence: id*100 + i})
			}
		}(w)
	}
	wg.Wait()
	if got := len(s.Events); got != 800 {
		t.Errorf("Events len = %d, want 800 (no events lost to races)", got)
	}
}
