package ui

import (
	"strings"
	"testing"

	"gordian-tui/internal/state"
)

func TestToolChainSpawnRendersParentArrowChild(t *testing.T) {
	ev := state.LiveEvent{
		Type: "pipeline.tool_chain.spawned",
		Tool: "nuclei",
		Payload: map[string]interface{}{
			"parent_tools": []interface{}{"subfinder", "httpx"},
			"child_tool":   "nuclei",
			"target":       "api.example.com",
		},
		Timestamp: "2026-05-20T12:34:56",
	}
	out := formatLogEvent(ev, 120)
	if !strings.Contains(out, "CHAIN") {
		t.Errorf("expected CHAIN marker, got %q", out)
	}
	if !strings.Contains(out, "subfinder") || !strings.Contains(out, "httpx") {
		t.Errorf("parent tools missing: %q", out)
	}
	if !strings.Contains(out, "nuclei") {
		t.Errorf("child tool missing: %q", out)
	}
	if !strings.Contains(out, "api.example.com") {
		t.Errorf("target missing: %q", out)
	}
	if !strings.Contains(out, "──▶") {
		t.Errorf("arrow missing: %q", out)
	}
}

func TestToolChainSpawnFallsBackWhenPayloadMissing(t *testing.T) {
	// No parent_tools / child_tool — should still render without panic.
	ev := state.LiveEvent{
		Type:      "pipeline.tool_chain.spawned",
		Tool:      "nuclei",
		Timestamp: "2026-05-20T12:34:56",
	}
	out := formatLogEvent(ev, 120)
	if !strings.Contains(out, "scan") {
		t.Errorf("expected fallback 'scan' parent label, got %q", out)
	}
	if !strings.Contains(out, "nuclei") {
		t.Errorf("child tool from ev.Tool missing: %q", out)
	}
}

func TestNonChainEventStillUsesDefaultFormatter(t *testing.T) {
	ev := state.LiveEvent{
		Type:      "pipeline.tick",
		Tool:      "hub",
		Level:     "info",
		Message:   "ok",
		Timestamp: "2026-05-20T12:34:56",
	}
	out := formatLogEvent(ev, 120)
	if strings.Contains(out, "CHAIN") || strings.Contains(out, "──▶") {
		t.Errorf("non-chain event should not use chain formatter: %q", out)
	}
}
