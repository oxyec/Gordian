package api

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func TestClientSendsAPIKey(t *testing.T) {
	t.Setenv("GORDIAN_API_KEY", "test-only-not-a-secret")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-Key") != "test-only-not-a-secret" {
			t.Error("API key missing")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer server.Close()
	client := NewClient(server.URL)
	if _, err := client.GetInfo(); err != nil {
		t.Fatal(err)
	}
	if _, err := client.StartScan(ScanStartRequest{}); err != nil {
		t.Fatal(err)
	}
}

func TestClientDoesNotForwardKeyOnRedirect(t *testing.T) {
	t.Setenv("GORDIAN_API_KEY", "test-only-not-a-secret")
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("client followed a redirect")
	}))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer source.Close()
	if _, err := NewClient(source.URL).GetInfo(); err == nil {
		t.Fatal("expected redirect rejection")
	}
}

// The server rejects these as server-owned (api/models.py); a client that
// sends them gets a 422 instead of a scan.
func TestScanStartRequestOmitsServerOwnedFields(t *testing.T) {
	serverOwned := map[string]bool{
		"output_dir": true, "tool_bin": true, "tool_extra_args": true, "tool_command": true,
		"full_control": true, "cve_profile": true, "cve_auto_download": true, "cve_sync_policy": true,
	}
	typ := reflect.TypeOf(ScanStartRequest{})
	for i := 0; i < typ.NumField(); i++ {
		name := strings.Split(typ.Field(i).Tag.Get("json"), ",")[0]
		if serverOwned[name] {
			t.Errorf("ScanStartRequest.%s sends server-owned field %q", typ.Field(i).Name, name)
		}
	}
}
