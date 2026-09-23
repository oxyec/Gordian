package ui

import (
	"testing"

	"gordian-tui/internal/state"
)

func newTestModel() AppModel {
	return NewAppModel("http://127.0.0.1:8000", "ws://127.0.0.1:8000/api/v1/live")
}

func TestApplyLiveEventToolStartFlipsRunning(t *testing.T) {
	m := newTestModel()
	m.applyLiveEvent(state.LiveEvent{Type: "offensive.tool_start", Tool: "nuclei"})

	for _, tool := range m.state.Tools {
		if tool.Name == "nuclei" && !tool.Running {
			t.Fatalf("nuclei should be Running after tool_start, got %+v", tool)
		}
	}
}

func TestApplyLiveEventToolDoneClearsRunning(t *testing.T) {
	m := newTestModel()
	m.state.SetToolRunning("nuclei", true)
	m.applyLiveEvent(state.LiveEvent{Type: "offensive.tool_done", Tool: "nuclei"})

	for _, tool := range m.state.Tools {
		if tool.Name == "nuclei" && tool.Running {
			t.Fatalf("nuclei should be cleared after tool_done")
		}
	}
}

func TestApplyLiveEventFindingPushesToStateAndBumpsCounter(t *testing.T) {
	m := newTestModel()
	m.state.CurrentScan.Findings = 2
	ev := state.LiveEvent{
		Type:    "offensive.finding",
		Tool:    "nuclei",
		Message: "rce on host-x",
		Payload: map[string]interface{}{
			"narrative":      "Nuclei identified critical RCE",
			"confidence":     0.9,
			"target_host_id": "host-x",
		},
	}
	m.applyLiveEvent(ev)

	got := m.state.GetFindings(0)
	if len(got) != 1 {
		t.Fatalf("expected 1 finding pushed, got %d", len(got))
	}
	if got[0].Narrative == "" || got[0].Confidence != 0.9 || got[0].Target != "host-x" {
		t.Errorf("payload not unpacked correctly: %+v", got[0])
	}
	if m.state.CurrentScan.Findings != 3 {
		t.Errorf("findings counter should bump 2→3, got %d", m.state.CurrentScan.Findings)
	}
}

func TestApplyLiveEventImpactSetsSnapshot(t *testing.T) {
	m := newTestModel()
	ev := state.LiveEvent{
		Type: "pipeline.offensive.impact",
		Payload: map[string]interface{}{
			"baseline_chains":  float64(3),
			"post_chains":      float64(7),
			"new_chains":       float64(4),
			"edges_added":      float64(12),
			"hosts_added":      float64(2),
			"new_target_hosts": []interface{}{"a.example.com", "b.example.com"},
		},
	}
	m.applyLiveEvent(ev)

	imp := m.state.GetImpact()
	if imp.BaselineChains != 3 || imp.PostChains != 7 || imp.NewChains != 4 {
		t.Errorf("impact chain counts wrong: %+v", imp)
	}
	if imp.EdgesAdded != 12 || imp.HostsAdded != 2 {
		t.Errorf("impact host/edge counts wrong: %+v", imp)
	}
	if len(imp.NewTargetHosts) != 2 || imp.NewTargetHosts[0] != "a.example.com" {
		t.Errorf("new_target_hosts not unpacked: %+v", imp.NewTargetHosts)
	}
}

func TestApplyLiveEventGraphBuiltUpdatesCounters(t *testing.T) {
	m := newTestModel()
	m.applyLiveEvent(state.LiveEvent{
		Type: "pipeline.transform.graph_built",
		Payload: map[string]interface{}{
			"nodes": float64(15),
			"edges": float64(42),
		},
	})
	if m.state.CurrentScan.Hosts != 15 || m.state.CurrentScan.Edges != 42 {
		t.Errorf("graph counters not applied: hosts=%d edges=%d",
			m.state.CurrentScan.Hosts, m.state.CurrentScan.Edges)
	}
}

func TestApplyLiveEventPathsBuiltSetsChainsAndTriggersRefetch(t *testing.T) {
	m := newTestModel()
	cmd := m.applyLiveEvent(state.LiveEvent{
		Type: "pipeline.transform.paths_built",
		Payload: map[string]interface{}{
			"kill_chains": float64(7),
		},
	})
	if m.state.CurrentScan.KillChains != 7 {
		t.Errorf("kill_chains counter not updated: %d", m.state.CurrentScan.KillChains)
	}
	if cmd == nil {
		t.Error("paths_built should return a refetch command, got nil")
	}
}

func TestApplyLiveEventUnknownTypeIsNoop(t *testing.T) {
	m := newTestModel()
	pre := len(m.state.GetFindings(0))
	cmd := m.applyLiveEvent(state.LiveEvent{Type: "totally.unknown.event"})
	if cmd != nil {
		t.Error("unknown event should not trigger a cmd")
	}
	if got := len(m.state.GetFindings(0)); got != pre {
		t.Error("unknown event mutated state")
	}
}
