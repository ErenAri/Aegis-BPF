package policy

import (
	"strings"
	"testing"

	v1alpha1 "github.com/ErenAri/aegis-operator/api/v1alpha1"
)

func TestTranslateEmpty(t *testing.T) {
	spec := v1alpha1.AegisPolicySpec{Mode: "audit"}
	result, err := TranslateToINI(spec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(result.INI, "version=5") {
		t.Error("expected version=5 header")
	}
	if result.SHA256 == "" {
		t.Error("expected non-empty hash")
	}
}

func TestTranslateFileRules(t *testing.T) {
	spec := v1alpha1.AegisPolicySpec{
		Mode: "enforce",
		FileRules: &v1alpha1.FileRules{
			Deny: []v1alpha1.FileRule{
				{Path: "/usr/bin/xmrig"},
				{Inode: "259:12345"},
			},
			Protect: []v1alpha1.FileRule{
				{Path: "/etc/shadow"},
			},
		},
	}
	result, err := TranslateToINI(spec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(result.INI, "[deny_path]") {
		t.Error("missing [deny_path] section")
	}
	if !strings.Contains(result.INI, "/usr/bin/xmrig") {
		t.Error("missing deny path entry")
	}
	if !strings.Contains(result.INI, "[deny_inode]") {
		t.Error("missing [deny_inode] section")
	}
	if !strings.Contains(result.INI, "259:12345") {
		t.Error("missing deny inode entry")
	}
	if !strings.Contains(result.INI, "[protect_path]") {
		t.Error("missing [protect_path] section")
	}
	if !strings.Contains(result.INI, "/etc/shadow") {
		t.Error("missing protect path entry")
	}
}

func TestTranslateNetworkRules(t *testing.T) {
	spec := v1alpha1.AegisPolicySpec{
		Mode: "enforce",
		NetworkRules: &v1alpha1.NetworkRules{
			Deny: []v1alpha1.NetworkRule{
				{IP: "10.0.0.1"},
				{CIDR: "192.168.0.0/16"},
				{Port: 4444, Protocol: "tcp", Direction: "outbound"},
				{IP: "10.0.0.2", Port: 8080, Protocol: "tcp", Direction: "outbound"},
			},
		},
	}
	result, err := TranslateToINI(spec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(result.INI, "[deny_ip]") {
		t.Error("missing [deny_ip] section")
	}
	if !strings.Contains(result.INI, "[deny_cidr]") {
		t.Error("missing [deny_cidr] section")
	}
	if !strings.Contains(result.INI, "[deny_port]") {
		t.Error("missing [deny_port] section")
	}
	if !strings.Contains(result.INI, "[deny_ip_port]") {
		t.Error("missing [deny_ip_port] section")
	}
	if !strings.Contains(result.INI, "10.0.0.2:tcp:8080:outbound") {
		t.Error("missing ip:port entry")
	}
}

func TestTranslateKernelRules(t *testing.T) {
	spec := v1alpha1.AegisPolicySpec{
		Mode: "enforce",
		KernelRules: &v1alpha1.KernelRules{
			BlockPtrace:     true,
			BlockModuleLoad: true,
			BlockBpfSyscall: true,
		},
	}
	result, err := TranslateToINI(spec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, section := range []string{"[deny_ptrace]", "[deny_module_load]", "[deny_bpf]"} {
		if !strings.Contains(result.INI, section) {
			t.Errorf("missing %s section", section)
		}
	}
}

func TestTranslateExecRules(t *testing.T) {
	allowHash := "a3b1c2d4e5f678900000000000000000a3b1c2d4e5f678900000000000000001"
	denyHash := "d4e5f678900000001a3b1c2d4e5f67890a3b1c2d4e5f67890a3b1c2d4e5f6789"
	spec := v1alpha1.AegisPolicySpec{
		Mode: "enforce",
		ExecRules: &v1alpha1.ExecRules{
			AllowBinaryHashes: []string{allowHash},
			DenyBinaryHashes:  []string{denyHash},
		},
	}
	result, err := TranslateToINI(spec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(result.INI, "[allow_binary_hash]") {
		t.Error("missing [allow_binary_hash]")
	}
	if !strings.Contains(result.INI, "sha256:"+allowHash) {
		t.Error("missing allow hash entry")
	}
	if !strings.Contains(result.INI, "[deny_binary_hash]") {
		t.Error("missing [deny_binary_hash]")
	}
	if !strings.Contains(result.INI, "sha256:"+denyHash) {
		t.Error("missing deny hash entry")
	}
}

func TestTranslateDefaultProtocolAndDirection(t *testing.T) {
	spec := v1alpha1.AegisPolicySpec{
		Mode: "enforce",
		NetworkRules: &v1alpha1.NetworkRules{
			Deny: []v1alpha1.NetworkRule{
				{Port: 9999},
			},
		},
	}
	result, err := TranslateToINI(spec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Defaults: protocol=tcp, direction=outbound
	if !strings.Contains(result.INI, "tcp:9999:outbound") {
		t.Error("expected default tcp:9999:outbound")
	}
}

func TestDeterministicHash(t *testing.T) {
	spec := v1alpha1.AegisPolicySpec{
		Mode: "enforce",
		FileRules: &v1alpha1.FileRules{
			Deny: []v1alpha1.FileRule{{Path: "/tmp/test"}},
		},
	}
	r1, _ := TranslateToINI(spec)
	r2, _ := TranslateToINI(spec)
	if r1.SHA256 != r2.SHA256 {
		t.Error("same input should produce same hash")
	}
}

func TestMergePolicies(t *testing.T) {
	p1 := TranslateResult{
		INI:    "version=5\n[deny_path]\n/usr/bin/a\n\n",
		SHA256: "aaa",
	}
	p2 := TranslateResult{
		INI:    "version=5\n[deny_path]\n/usr/bin/b\n\n[deny_ip]\n10.0.0.1\n\n",
		SHA256: "bbb",
	}
	merged := MergePolicies([]TranslateResult{p1, p2})
	if !strings.Contains(merged.INI, "/usr/bin/a") {
		t.Error("missing entry from policy 1")
	}
	if !strings.Contains(merged.INI, "/usr/bin/b") {
		t.Error("missing entry from policy 2")
	}
	if !strings.Contains(merged.INI, "[deny_ip]") {
		t.Error("missing section from policy 2")
	}
}

func TestMergeDeduplicates(t *testing.T) {
	p1 := TranslateResult{INI: "version=5\n[deny_path]\n/usr/bin/a\n\n", SHA256: "a"}
	p2 := TranslateResult{INI: "version=5\n[deny_path]\n/usr/bin/a\n\n", SHA256: "a"}
	merged := MergePolicies([]TranslateResult{p1, p2})
	count := strings.Count(merged.INI, "/usr/bin/a")
	if count != 1 {
		t.Errorf("expected 1 occurrence, got %d", count)
	}
}

func TestMergePoliciesDeterministic(t *testing.T) {
	p1 := TranslateResult{
		INI:    "version=5\n[deny_path]\n/usr/bin/a\n\n",
		SHA256: "aaa",
	}
	p2 := TranslateResult{
		INI:    "version=5\n[deny_path]\n/usr/bin/b\n\n[deny_ip]\n10.0.0.1\n\n",
		SHA256: "bbb",
	}

	input1 := []TranslateResult{p1, p2}
	input2 := []TranslateResult{p1, p2}

	merged1 := MergePolicies(input1)
	merged2 := MergePolicies(input2)

	if merged1.SHA256 != merged2.SHA256 {
		t.Error("same merged input should produce same hash")
	}
	if merged1.INI != merged2.INI {
		t.Error("same merged input should produce same INI output")
	}
}
