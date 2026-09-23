package ui

import (
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
)

type ToastLevel int

const (
	ToastInfo ToastLevel = iota
	ToastWarning
	ToastError
	ToastSuccess
)

type Toast struct {
	Message  string
	Level    ToastLevel
	Deadline time.Time
}

type ToastManager struct {
	toasts []Toast
}

func NewToastManager() *ToastManager {
	return &ToastManager{}
}

func (tm *ToastManager) Add(msg string, level ToastLevel, duration time.Duration) {
	tm.toasts = append(tm.toasts, Toast{
		Message:  msg,
		Level:    level,
		Deadline: time.Now().Add(duration),
	})
}

func (tm *ToastManager) Update() {
	now := time.Now()
	filtered := make([]Toast, 0, len(tm.toasts))
	for _, t := range tm.toasts {
		if now.Before(t.Deadline) {
			filtered = append(filtered, t)
		}
	}
	tm.toasts = filtered
}

func (tm *ToastManager) HasActive() bool {
	tm.Update()
	return len(tm.toasts) > 0
}

func (tm *ToastManager) Render(width int) string {
	if !tm.HasActive() {
		return ""
	}
	if width < 8 {
		width = 8
	}

	// Show the latest active toast.
	t := tm.toasts[len(tm.toasts)-1]

	var style lipgloss.Style
	icon := "i"
	switch t.Level {
	case ToastError:
		style = ErrorOverlay
		icon = "x"
	case ToastWarning:
		style = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(ColorAmber).
			Background(lipgloss.Color("#1a1000")).
			Foreground(ColorAmber).
			Bold(true).
			Padding(0, 2)
		icon = "!"
	case ToastSuccess:
		style = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(ColorMatrixGreen).
			Background(lipgloss.Color("#001a00")).
			Foreground(ColorMatrixGreen).
			Bold(true).
			Padding(0, 2)
		icon = "+"
	default:
		style = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(ColorNeonCyan).
			Background(lipgloss.Color("#001a1a")).
			Foreground(ColorNeonCyan).
			Bold(true).
			Padding(0, 2)
	}

	msg := truncate(strings.TrimSpace(t.Message), width-8)
	if msg == "" {
		msg = "(empty message)"
	}
	line := icon + " " + msg
	return style.Width(width - 4).Align(lipgloss.Center).Render(line)
}
