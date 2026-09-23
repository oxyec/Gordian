/*
Gordian TUI — Command Center Entry Point.

Connects to the Gordian Python API backend and provides a full
cyberpunk terminal interface for attack-path intelligence.

Usage:

	go run ./cmd/gordian
	go run ./cmd/gordian --api http://localhost:9000
	go run ./cmd/gordian --help
*/
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"gordian-tui/internal/ui"
)

var version = "2.0.0-tui"

func normalizeBaseURL(raw string) string {
	return strings.TrimRight(strings.TrimSpace(raw), "/")
}

func deriveWSURL(apiBase string, override string) string {
	if strings.TrimSpace(override) != "" {
		return strings.TrimSpace(override)
	}

	base := normalizeBaseURL(apiBase)
	base = strings.Replace(base, "http://", "ws://", 1)
	base = strings.Replace(base, "https://", "wss://", 1)
	return base + "/api/v1/live"
}

func isBackendRunning(url string) bool {
	client := http.Client{Timeout: 500 * time.Millisecond}
	req, err := http.NewRequest(http.MethodGet, normalizeBaseURL(url)+"/api/v1/info", nil)
	if err != nil {
		return false
	}
	req.Header.Set("X-API-Key", os.Getenv("GORDIAN_API_KEY"))
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func startBackend() (*exec.Cmd, error) {
	// Look for main.py relative to current directory
	paths := []string{"main.py", "../main.py", "../../main.py"}
	var mainPy string
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			mainPy = p
			break
		}
	}
	if mainPy == "" {
		return nil, fmt.Errorf("could not locate backend main.py")
	}

	pyCmd := "python"
	if _, err := exec.LookPath("python"); err != nil {
		if _, err := exec.LookPath("python3"); err == nil {
			pyCmd = "python3"
		}
	}

	cmd := exec.Command(pyCmd, mainPy, "--headless")

	logFile, err := os.OpenFile("gordian-backend.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err == nil {
		defer logFile.Close()
		cmd.Stdout = logFile
		cmd.Stderr = logFile
	}

	err = cmd.Start()
	return cmd, err
}

func stopBackend(cmd *exec.Cmd) error {
	if cmd == nil || cmd.Process == nil {
		return nil
	}

	if err := cmd.Process.Signal(os.Interrupt); err != nil {
		return cmd.Process.Kill()
	}

	done := make(chan error, 1)
	go func() {
		_, err := cmd.Process.Wait()
		done <- err
	}()

	select {
	case <-done:
		return nil
	case <-time.After(3 * time.Second):
		return cmd.Process.Kill()
	}
}

func main() {
	apiBase := flag.String("api", "http://localhost:8000", "Gordian API base URL")
	wsURL := flag.String("ws", "", "WebSocket URL (auto-derived from --api if empty)")
	showVersion := flag.Bool("version", false, "Print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("gordian-tui %s\n", version)
		os.Exit(0)
	}

	api := normalizeBaseURL(*apiBase)
	if len(strings.TrimSpace(os.Getenv("GORDIAN_API_KEY"))) < 32 {
		fmt.Fprintln(os.Stderr, "Set GORDIAN_API_KEY to the same random secret (at least 32 characters) used by the backend.")
		return
	}

	// Derive WebSocket URL from API base
	ws := deriveWSURL(api, *wsURL)

	// Configure logging
	logFile, err := os.OpenFile("gordian-tui.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err == nil {
		log.SetOutput(logFile)
		defer logFile.Close()
	}

	log.Printf("Gordian TUI %s starting — api=%s ws=%s", version, api, ws)

	var backendCmd *exec.Cmd
	defer func() {
		if backendCmd != nil {
			log.Println("Gracefully shutting down backend...")
			if err := stopBackend(backendCmd); err != nil {
				log.Printf("Backend stop error: %v", err)
			}
		}
	}()

	// Try to start backend automatically if the API isn't responding
	if !isBackendRunning(api) && (api == "http://localhost:8000" || api == "http://127.0.0.1:8000") {
		log.Println("Backend not responding, attempting auto-start...")
		backendCmd, err = startBackend()
		if err == nil {
			log.Printf("Started background API backend with PID %d", backendCmd.Process.Pid)
			// Give it a moment to boot
			time.Sleep(1500 * time.Millisecond)
		} else {
			log.Printf("Could not auto-start backend: %v", err)
		}
	} else {
		log.Println("Backend already running.")
	}

	// Create and run the Bubble Tea program
	model := ui.NewAppModel(api, ws)
	p := tea.NewProgram(model,
		tea.WithAltScreen(),
		tea.WithMouseCellMotion(),
	)

	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "gordian-tui error: %v\n", err)
		os.Exit(1)
	}
}
