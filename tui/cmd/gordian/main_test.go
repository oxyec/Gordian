package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDeriveWSURLUsesAPIBaseWhenOverrideEmpty(t *testing.T) {
	got := deriveWSURL("http://localhost:8000/", "")
	want := "ws://localhost:8000/api/v1/live"
	if got != want {
		t.Fatalf("deriveWSURL() = %q, want %q", got, want)
	}
}

func TestDeriveWSURLSupportsHTTPSBase(t *testing.T) {
	got := deriveWSURL("https://api.example.com", "")
	want := "wss://api.example.com/api/v1/live"
	if got != want {
		t.Fatalf("deriveWSURL() = %q, want %q", got, want)
	}
}

func TestDeriveWSURLRespectsExplicitOverride(t *testing.T) {
	got := deriveWSURL("http://localhost:8000", "wss://socket.example.com/custom")
	want := "wss://socket.example.com/custom"
	if got != want {
		t.Fatalf("deriveWSURL() override = %q, want %q", got, want)
	}
}

func TestIsBackendRunningReturnsTrueForHealthyDocs(t *testing.T) {
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/info" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer testServer.Close()

	if !isBackendRunning(testServer.URL) {
		t.Fatal("expected backend to be reported as running")
	}
}

func TestIsBackendRunningReturnsFalseOnServerError(t *testing.T) {
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer testServer.Close()

	if isBackendRunning(testServer.URL) {
		t.Fatal("expected backend to be reported as not running")
	}
}
