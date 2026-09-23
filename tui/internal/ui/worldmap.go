/*
World map widget — geographically accurate 53-char ASCII mercator projection
matching the Python WORLD_MAP_TEMPLATE design. Inner content area is 50×7,
bordered by | on cols 1 and 52, with . and ' corners. Land is marked with #.

Projection formula (inner content: cols 2..51, rows 1..7):
  col = 2 + round((lon+180)/360 * 49)
  row = 1 + round((90-lat)/180 * 6)
*/
package ui

import (
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"gordian-tui/internal/state"
)



// Land/ocean/border styles
var (
	mapLandStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("#4CAF50")).Background(ColorBg) // Brightened from #2d6b27
	mapLabelStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("#81C784")).Background(ColorBg) // Brightened from #3a8a34
	mapOceanStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("#2A4365")).Background(ColorBg) // Brightened from #0d1a2e
	mapBorderStyle = lipgloss.NewStyle().Foreground(ColorDimCyan).Background(ColorBg)
)

// geoToMapCoord converts lat/lon to (row, col) indices in the new 140x60 grid.
func geoToMapCoord(lat, lon float64) (row, col int) {
	col = int(math.Round((lon + 180.0) / 360.0 * 139.0))
	row = int(math.Round((90.0 - lat) / 180.0 * 59.0))
	if col < 0 { col = 0 }
	if col > 139 { col = 139 }
	if row < 0 { row = 0 }
	if row > 59 { row = 59 }
	return row, col
}

// RenderWorldMap draws the high-res Braille world map with geo-markers, crosshair, and tooltips.
func RenderWorldMap(markers []state.GeoMarker, width, height int, focused bool, cursorX, cursorY int) string {
	var b strings.Builder

	// The total size of the panel box must match the application layout
	boxW := width - 4
	boxH := height - 2
	if boxW < 1 { boxW = 1 }
	if boxH < 1 { boxH = 1 }

	// The PanelBorder has 2 chars for borders and 2 chars for padding.
	innerW := boxW - 4
	innerH := boxH - 2
	if innerW < 1 { innerW = 1 }
	if innerH < 1 { innerH = 1 }

	// Calculate viewport camera centered on cursor
	viewX := cursorX - innerW/2
	viewY := cursorY - innerH/2

	// Clamp viewport to map boundaries
	if viewX < 0 { viewX = 0 }
	if viewY < 0 { viewY = 0 }
	if viewX+innerW > 140 { viewX = 140 - innerW }
	if viewY+innerH > 60 { viewY = 60 - innerH }
	// If viewport is larger than map, re-center
	if innerW >= 140 { viewX = -(innerW - 140) / 2 }
	if innerH >= 60 { viewY = -(innerH - 60) / 2 }

	blink := time.Now().UnixMilli()%800 < 400
	activeCount := 0

	// Check if cursor hovers any marker
	var hoveredMarker *state.GeoMarker

	// Render map viewport
	mapGridHeight := innerH - 2 // Reserve 1 line for header, 1 for legend
	if mapGridHeight < 1 { mapGridHeight = 1 }
	for screenY := 0; screenY < mapGridHeight; screenY++ {
		mapY := viewY + screenY
		line := ""
		for screenX := 0; screenX < innerW; screenX++ {
			mapX := viewX + screenX
			
			// Out of bounds (padding)
			if mapX < 0 || mapX >= 140 || mapY < 0 || mapY >= 60 {
				line += mapOceanStyle.Render(" ")
				continue
			}

			// Check for markers and cursor
			isCursor := focused && mapX == cursorX && mapY == cursorY
			
			markerAtLocation := false
			markerIcon := ' '
			var currentMarker *state.GeoMarker

			for i, m := range markers {
				r, c := geoToMapCoord(m.Latitude, m.Longitude)
				if r == mapY && c == mapX {
					markerAtLocation = true
					currentMarker = &markers[i]
					if m.Active && blink {
						markerIcon = '✦'
						if activeCount < len(markers) { // Count roughly
							activeCount++
						}
					} else if m.Active {
						markerIcon = '⚡'
					} else {
						markerIcon = '◉'
					}
					
					if isCursor {
						hoveredMarker = currentMarker
					}
					break
				}
			}

			if isCursor {
				// Use '+' instead of '⌖' to prevent double-width character wrapping issues in WSL
				line += TitleStyle.Render("+")
			} else if markerAtLocation {
				if markerIcon == '◉' {
					line += StatusWarning.Render(string(markerIcon))
				} else {
					line += GlitchStyle.Render(string(markerIcon))
				}
			} else {
				// Base map char
				runes := []rune(worldMapRows[mapY])
				ch := ' '
				if mapX < len(runes) {
					ch = runes[mapX]
				}
				if ch == ' ' {
					line += mapOceanStyle.Render(" ")
				} else {
					line += mapLandStyle.Render(string(ch))
				}
			}
		}
		b.WriteString(line)
		b.WriteString("\n")
	}

	// Legend & Tooltip
	var legend string
	if hoveredMarker != nil {
		hostStr := hoveredMarker.Hostname
		if hostStr == "" { hostStr = hoveredMarker.IP }
		legend = fmt.Sprintf("  %s %s RISK:%d", 
			TitleStyle.Render("+ TARGET:"), 
			HighlightStyle.Render(hostStr),
			hoveredMarker.RiskScore)
	} else if focused {
		legend = fmt.Sprintf("  %s %d,%d", TitleStyle.Render("+ NAVIGATING"), cursorX, cursorY)
	} else {
		legend = fmt.Sprintf("  %s active  %s target", GlitchStyle.Render("⚡"), StatusWarning.Render("◉"))
	}

	// Header
	headerText := "⊕ GLOBAL THREAT MAP"
	if len(markers) > 0 {
		headerText += fmt.Sprintf("  %s", DimStyle.Render(fmt.Sprintf("[%d targets]", len(markers))))
	}
	
	header := PanelHeader.Render(headerText)
	
	// Stitch together
	finalContent := header + "\n" + b.String() + legend
	finalContent = truncateLines(finalContent, innerH)
	
	border := PanelBorder
	if focused {
		border = PanelBorderActive
	}
	// Important: use boxW and boxH to strictly match layout expectations
	return border.Width(boxW).Height(boxH).Render(finalContent)
}
