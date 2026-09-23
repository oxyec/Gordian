/*
Live log panel — scrolling event feed from the WebSocket stream.
Color-coded by level and type, with glitch trigger on critical findings.
*/
package ui

import (
	"fmt"
	"strings"

	"gordian-tui/internal/state"
)

// RenderLiveLog renders the scrolling event log panel.
func RenderLiveLog(events []state.LiveEvent, width, height int) string {
	var b strings.Builder

	w := width - 4
	h := height - 2
	if w < 1 {
		w = 1
	}
	if h < 1 {
		h = 1
	}

	b.WriteString(PanelHeader.Render(fmt.Sprintf("◈ LIVE EVENT STREAM  %s",
		DimStyle.Render(fmt.Sprintf("[%d events]", len(events))))))
	b.WriteString("\n")

	if len(events) == 0 {
		b.WriteString("\n")
		b.WriteString(DimStyle.Render("  ○  awaiting events from API…"))
		b.WriteString("\n")
		content := truncateLines(b.String(), h)
		return PanelBorder.Width(w).Height(h).Render(content)
	}

	// Visible window: header(1) + counter(1) = 2 overhead lines
	maxVisible := h - 2
	if maxVisible < 1 {
		maxVisible = 1
	}

	visible := events
	startIdx := 0
	if len(visible) > maxVisible {
		startIdx = len(visible) - maxVisible
		visible = visible[startIdx:]
	}

	for _, ev := range visible {
		line := formatLogEvent(ev, w)
		b.WriteString(line)
		b.WriteString("\n")
	}

	// Trailing counter with scroll position indicator
	totalEvents := len(events)
	showingFrom := startIdx + 1
	showingTo := startIdx + len(visible)
	scrollInfo := fmt.Sprintf("showing %d–%d of %d", showingFrom, showingTo, totalEvents)
	b.WriteString(DimStyle.Render(fmt.Sprintf("  ─── %s  ───", scrollInfo)))

	content := truncateLines(b.String(), h)
	return PanelBorder.Width(w).Height(h).Render(content)
}

func formatLogEvent(ev state.LiveEvent, maxWidth int) string {
	// Special render for tool_chain spawn events: show the recon→exploit
	// lineage as a visible arrow chain so the operator can watch tools feed
	// each other instead of reading a flat log.
	if ev.Type == "pipeline.tool_chain.spawned" {
		return formatToolChainSpawn(ev, maxWidth)
	}
	// Timestamp — extract HH:MM:SS
	ts := ev.Timestamp
	switch {
	case len(ts) >= 19:
		ts = ts[11:19]
	case len(ts) >= 8:
		ts = ts[len(ts)-8:]
	default:
		ts = "??:??:??"
	}

	// Level icon + style
	level := strings.ToUpper(ev.Level)
	var levelStr string
	switch level {
	case "ERROR":
		levelStr = LogError.Render("[✗]")
	case "WARNING", "WARN":
		levelStr = LogWarning.Render("[!]")
	case "INFO":
		levelStr = LogInfo.Render("[·]")
	default:
		levelStr = DimStyle.Render("[·]")
	}

	// Event type badge — color by category
	typeStr := ev.Type
	if len(typeStr) > 16 {
		typeStr = typeStr[:16]
	}
	var typeBadge string
	switch {
	case strings.Contains(ev.Type, "offensive"), strings.Contains(ev.Type, "exploit"):
		typeBadge = FindingStyle.Render(fmt.Sprintf("%-16s", typeStr))
	case strings.Contains(ev.Type, "dijkstra"), strings.Contains(ev.Type, "path"):
		typeBadge = LogDijkstra.Render(fmt.Sprintf("%-16s", typeStr))
	case strings.Contains(ev.Type, "pipeline"):
		typeBadge = StatusRunning.Render(fmt.Sprintf("%-16s", typeStr))
	case strings.Contains(ev.Type, "scan"):
		typeBadge = LogInfo.Render(fmt.Sprintf("%-16s", typeStr))
	default:
		typeBadge = LogTool.Render(fmt.Sprintf("%-16s", typeStr))
	}

	// Tool tag
	tool := ev.Tool
	if tool == "" {
		tool = "hub"
	}
	if len(tool) > 10 {
		tool = tool[:10]
	}
	toolTag := DimStyle.Render(fmt.Sprintf("%-10s", tool))

	// Message — truncate to available width
	// layout: "  " + ts(8) + " " + level(3) + " " + type(16) + " " + tool(10) + " " + msg
	overhead := 2 + 8 + 1 + 3 + 1 + 16 + 1 + 10 + 1
	msgWidth := maxWidth - overhead
	if msgWidth < 4 {
		msgWidth = 4
	}
	msg := ev.Message
	if len(msg) > msgWidth {
		msg = msg[:msgWidth-1] + "…"
	}

	var msgStyle string
	switch level {
	case "ERROR":
		msgStyle = LogError.Render(msg)
	case "WARNING", "WARN":
		msgStyle = LogWarning.Render(msg)
	default:
		msgStyle = BaseStyle.Render(msg)
	}

	return fmt.Sprintf("  %s %s %s %s %s",
		LogTimestamp.Render(ts),
		levelStr,
		typeBadge,
		toolTag,
		msgStyle,
	)
}

// formatToolChainSpawn renders one pipeline.tool_chain.spawned event as a
// compact lineage arrow: `12:34:56 ▸ subfinder+httpx ──▶ nuclei  (api.example.com)`.
// Highlights the feeding loop visually so the operator can see recon results
// turning into exploit targets in real time.
func formatToolChainSpawn(ev state.LiveEvent, maxWidth int) string {
	ts := ev.Timestamp
	switch {
	case len(ts) >= 19:
		ts = ts[11:19]
	case len(ts) >= 8:
		ts = ts[len(ts)-8:]
	default:
		ts = "??:??:??"
	}

	parents := "scan"
	if raw, ok := ev.Payload["parent_tools"].([]interface{}); ok && len(raw) > 0 {
		names := make([]string, 0, len(raw))
		for _, item := range raw {
			if s, ok := item.(string); ok {
				names = append(names, s)
			}
		}
		if len(names) > 0 {
			parents = strings.Join(names, "+")
		}
	}

	child := ev.Tool
	if v, ok := ev.Payload["child_tool"].(string); ok && v != "" {
		child = v
	}
	if child == "" {
		child = "?"
	}

	target := ""
	if v, ok := ev.Payload["target"].(string); ok {
		target = v
	}

	parentTag := categoryStyle(strings.Split(parents, "+")[0]).Render(parents)
	childTag := categoryStyle(child).Render(child)
	arrow := StatusRunning.Render(" ──▶ ")

	line := fmt.Sprintf("  %s %s  %s%s%s",
		LogTimestamp.Render(ts),
		StatusRunning.Render("▸ CHAIN"),
		parentTag, arrow, childTag,
	)
	if target != "" {
		// Trim target if the line would overflow.
		tail := DimStyle.Render(fmt.Sprintf("  (%s)", target))
		if len(line)+len(target)+5 > maxWidth && maxWidth > 20 {
			room := maxWidth - len(line) - 5
			if room < 6 {
				room = 6
			}
			tail = DimStyle.Render(fmt.Sprintf("  (%s…)", target[:room]))
		}
		line += tail
	}
	return line
}
