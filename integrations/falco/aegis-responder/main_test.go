package main

import (
	"bufio"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func baseCfg() *Config {
	return &Config{
		Socket:      "/tmp/x.sock",
		MinPriority: "warning",
		Rules: []RuleAction{
			{Rule: "Write below binary dir", Action: "block-file", Field: "fd.name"},
			{Rule: "Unexpected outbound connection", Action: "deny-ip", Field: "fd.sip"},
			{Rule: "Contact cloud metadata", Action: "deny-cidr", Field: "net.cidr"},
		},
	}
}

func TestDecide_FileBlock(t *testing.T) {
	a := FalcoAlert{Rule: "Write below binary dir", Priority: "Error",
		OutputFields: map[string]interface{}{"fd.name": "/usr/bin/evil"}}
	verb, arg, ok := decide(a, baseCfg())
	if !ok || verb != "/block/add" || arg != "/usr/bin/evil" {
		t.Fatalf("got verb=%q arg=%q ok=%v", verb, arg, ok)
	}
}

func TestDecide_NetDeny(t *testing.T) {
	a := FalcoAlert{Rule: "Unexpected outbound connection", Priority: "Warning",
		OutputFields: map[string]interface{}{"fd.sip": "203.0.113.7"}}
	verb, arg, ok := decide(a, baseCfg())
	if !ok || verb != "/network/deny/ip" || arg != "203.0.113.7" {
		t.Fatalf("got verb=%q arg=%q ok=%v", verb, arg, ok)
	}
}

func TestDecide_UnknownRuleNoAction(t *testing.T) {
	a := FalcoAlert{Rule: "Some benign rule", Priority: "Critical",
		OutputFields: map[string]interface{}{"fd.name": "/etc/passwd"}}
	if _, _, ok := decide(a, baseCfg()); ok {
		t.Fatal("unlisted rule must not trigger enforcement")
	}
}

func TestDecide_BelowMinPriority(t *testing.T) {
	a := FalcoAlert{Rule: "Write below binary dir", Priority: "Notice",
		OutputFields: map[string]interface{}{"fd.name": "/usr/bin/evil"}}
	if _, _, ok := decide(a, baseCfg()); ok {
		t.Fatal("alert below min_priority must be ignored")
	}
}

func TestDecide_MissingFieldNoAction(t *testing.T) {
	a := FalcoAlert{Rule: "Write below binary dir", Priority: "Error",
		OutputFields: map[string]interface{}{"other": "x"}}
	if _, _, ok := decide(a, baseCfg()); ok {
		t.Fatal("missing target field must not trigger enforcement")
	}
}

// A target carrying a newline could smuggle a second control command; it must be rejected.
func TestDecide_RejectsProtocolInjection(t *testing.T) {
	a := FalcoAlert{Rule: "Write below binary dir", Priority: "Error",
		OutputFields: map[string]interface{}{"fd.name": "/usr/bin/evil\nPOST /block/clear"}}
	if _, _, ok := decide(a, baseCfg()); ok {
		t.Fatal("target with embedded newline must be rejected")
	}
}

func TestValidTarget(t *testing.T) {
	cases := []struct {
		verb, arg string
		want      bool
	}{
		{"/block/add", "/usr/bin/evil", true},
		{"/block/add", "relative/path", false},
		{"/block/add", "/usr/../etc/passwd", false},
		{"/block/add", "/ok\nPOST /block/clear", false},
		{"/network/deny/ip", "203.0.113.7", true},
		{"/network/deny/ip", "2001:db8::1", true},
		{"/network/deny/ip", "not-an-ip", false},
		{"/network/deny/ip", "203.0.113.7\n", false},
		{"/network/deny/cidr", "10.0.0.0/8", true},
		{"/network/deny/cidr", "10.0.0.0", false},
		{"/unknown/verb", "/anything", false},
	}
	for _, c := range cases {
		if got := validTarget(c.verb, c.arg); got != c.want {
			t.Errorf("validTarget(%q, %q) = %v, want %v", c.verb, c.arg, got, c.want)
		}
	}
}

// When auth_token is set, requests without the matching header are rejected.
func TestHandle_AuthRequired(t *testing.T) {
	cfg := baseCfg()
	cfg.AuthToken = "s3cret"
	cfg.DryRun = true
	h := &responder{cfg: cfg}
	body := `{"rule":"Write below binary dir","priority":"Error","output_fields":{"fd.name":"/usr/bin/evil"}}`

	// No token -> 401.
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.handle(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("missing token: got %d want 401", rec.Code)
	}

	// Correct token -> processed (dry-run 200).
	req = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("X-Aegis-Token", "s3cret")
	rec = httptest.NewRecorder()
	h.handle(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("valid token: got %d want 200", rec.Code)
	}
}

// An oversized body must be rejected rather than buffered into memory.
func TestHandle_BodyLimit(t *testing.T) {
	cfg := baseCfg()
	cfg.DryRun = true
	h := &responder{cfg: cfg}
	huge := `{"rule":"x","output_fields":{"fd.name":"` + strings.Repeat("A", maxBody+1) + `"}}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(huge))
	rec := httptest.NewRecorder()
	h.handle(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("oversized body: got %d want 400", rec.Code)
	}
}

// sendControl must speak the exact AegisBPF socket protocol: "POST <verb> <arg>\n".
func TestSendControl_SpeaksProtocol(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "a.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	got := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		line, _ := bufio.NewReader(c).ReadString('\n')
		got <- strings.TrimSpace(line)
		_, _ = c.Write([]byte(`{"status":"ok"}` + "\n\n"))
	}()

	reply, err := sendControl(sock, "/block/add", "/var/tmp/evil")
	if err != nil {
		t.Fatalf("sendControl: %v", err)
	}
	if r := <-got; r != "POST /block/add /var/tmp/evil" {
		t.Fatalf("server saw %q", r)
	}
	if !strings.Contains(reply, `"status":"ok"`) {
		t.Fatalf("reply %q", reply)
	}
}

func TestLoadConfig_DefaultsSocket(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "c.json")
	_ = os.WriteFile(p, []byte(`{"rules":[]}`), 0o644)
	c, err := loadConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.Socket != "/var/run/aegisbpf/aegisbpf.sock" {
		t.Fatalf("default socket not applied: %q", c.Socket)
	}
}
