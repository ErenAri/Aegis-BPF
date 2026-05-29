package policy

import (
	"strings"
	"testing"

	v1alpha1 "github.com/ErenAri/aegis-operator/api/v1alpha1"
)

func TestTranslateToAegisNext_FileRules(t *testing.T) {
	spec := v1alpha1.AegisPolicySpec{
		Mode: "enforce",
		FileRules: &v1alpha1.FileRules{
			Deny: []v1alpha1.FileRule{
				{Path: "/etc/shadow"},
				{Path: "/etc/passwd", Action: v1alpha1.RuleActionAllow},
			},
			Protect: []v1alpha1.FileRule{
				{Path: "/var/log/syslog"},
			},
		},
	}

	result, err := TranslateToAegisNext(spec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(result.INI, "file  path  /etc/shadow  deny") {
		t.Error("missing deny rule for /etc/shadow")
	}
	if !strings.Contains(result.INI, "file  path  /etc/passwd  allow") {
		t.Error("missing allow rule for /etc/passwd")
	}
	if !strings.Contains(result.INI, "fperm  path  /var/log/syslog  log") {
		t.Error("missing protect/log rule for syslog")
	}
}

func TestTranslateToAegisNext_NetworkRules(t *testing.T) {
	spec := v1alpha1.AegisPolicySpec{
		Mode: "enforce",
		NetworkRules: &v1alpha1.NetworkRules{
			Deny: []v1alpha1.NetworkRule{
				{Port: 4444, Direction: "outbound"},
				{Port: 31337, Direction: "inbound"},
			},
		},
	}

	result, err := TranslateToAegisNext(spec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(result.INI, "conn  port  4444  deny  kill") {
		t.Error("missing outbound deny for port 4444")
	}
	if !strings.Contains(result.INI, "bind  port  31337  deny  kill") {
		t.Error("missing inbound bind deny for port 31337")
	}
	if !strings.Contains(result.INI, "listen  port  31337  deny  kill") {
		t.Error("missing inbound listen deny for port 31337")
	}
}

func TestTranslateToAegisNext_ExecRules(t *testing.T) {
	spec := v1alpha1.AegisPolicySpec{
		Mode: "enforce",
		ExecRules: &v1alpha1.ExecRules{
			DenyComm: []string{"xmrig", "ncat"},
		},
	}

	result, err := TranslateToAegisNext(spec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(result.INI, "exec  comm  xmrig  deny  kill") {
		t.Error("missing deny for xmrig")
	}
	if !strings.Contains(result.INI, "exec  comm  ncat  deny  kill") {
		t.Error("missing deny for ncat")
	}
}

func TestTranslateToAegisNext_KernelRules(t *testing.T) {
	spec := v1alpha1.AegisPolicySpec{
		Mode: "enforce",
		KernelRules: &v1alpha1.KernelRules{
			BlockModuleLoad: true,
			BlockPtrace:     true,
		},
	}

	result, err := TranslateToAegisNext(spec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(result.INI, "kmod  comm  insmod  deny  kill") {
		t.Error("missing kmod deny for insmod")
	}
	if !strings.Contains(result.INI, "ptrace  comm  gdb  deny  kill") {
		t.Error("missing ptrace deny for gdb")
	}
}

func TestTranslateToAegisNext_AuditMode(t *testing.T) {
	spec := v1alpha1.AegisPolicySpec{
		Mode: "audit",
		ExecRules: &v1alpha1.ExecRules{
			DenyComm: []string{"xmrig"},
		},
	}

	result, err := TranslateToAegisNext(spec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(result.INI, "exec  comm  xmrig  log  kill") {
		t.Error("audit mode should use 'log' action, got: " + result.INI)
	}
}

func TestTranslateToAegisNext_SHA256NotEmpty(t *testing.T) {
	spec := v1alpha1.AegisPolicySpec{Mode: "enforce"}
	result, _ := TranslateToAegisNext(spec)
	if result.SHA256 == "" {
		t.Error("SHA256 hash should not be empty")
	}
	if len(result.SHA256) != 64 {
		t.Errorf("SHA256 hash should be 64 hex chars, got %d", len(result.SHA256))
	}
}

func TestMergeNextPolicies(t *testing.T) {
	p1 := TranslateResult{INI: "exec  comm  xmrig  deny  kill\nconn  port  4444  deny  kill\n"}
	p2 := TranslateResult{INI: "exec  comm  ncat  deny  kill\nconn  port  4444  deny  kill\n"}

	merged := MergeNextPolicies([]TranslateResult{p1, p2})

	lines := strings.Split(strings.TrimSpace(merged.INI), "\n")
	// Filter out comments.
	var rules []string
	for _, l := range lines {
		if !strings.HasPrefix(l, "#") && l != "" {
			rules = append(rules, l)
		}
	}

	if len(rules) != 3 {
		t.Errorf("expected 3 unique rules, got %d: %v", len(rules), rules)
	}
}
