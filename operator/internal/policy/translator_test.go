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

func TestTranslateMixedActions(t *testing.T) {
	spec := v1alpha1.AegisPolicySpec{
		Mode: "enforce",
		FileRules: &v1alpha1.FileRules{
			Deny: []v1alpha1.FileRule{
				{Path: "/etc/shadow"}, // unset action defaults to Block
				{Path: "/usr/bin/curl", Action: v1alpha1.RuleActionAllow},
				{Path: "/usr/bin/xmrig", Action: v1alpha1.RuleActionBlock},
			},
		},
		NetworkRules: &v1alpha1.NetworkRules{
			Deny: []v1alpha1.NetworkRule{
				{IP: "10.0.0.1"}, // default Block
				{IP: "10.0.0.2", Action: v1alpha1.RuleActionAllow},
			},
		},
	}
	result, err := TranslateToINI(spec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Block-action and default-action paths land in [deny_path].
	if !strings.Contains(result.INI, "[deny_path]") {
		t.Error("missing [deny_path] section")
	}
	if !strings.Contains(result.INI, "/etc/shadow") {
		t.Error("missing default-block path entry")
	}
	if !strings.Contains(result.INI, "/usr/bin/xmrig") {
		t.Error("missing explicit-block path entry")
	}

	// Allow-action paths land in [allow_path].
	if !strings.Contains(result.INI, "[allow_path]") {
		t.Error("missing [allow_path] section")
	}
	if !strings.Contains(result.INI, "/usr/bin/curl") {
		t.Error("missing allow path entry")
	}

	// Network rules: [deny_ip] for default, [allow_ip] for explicit Allow.
	if !strings.Contains(result.INI, "[deny_ip]") || !strings.Contains(result.INI, "10.0.0.1") {
		t.Error("missing deny_ip entry for default-Block rule")
	}
	if !strings.Contains(result.INI, "[allow_ip]") || !strings.Contains(result.INI, "10.0.0.2") {
		t.Error("missing allow_ip entry for explicit-Allow rule")
	}
}

func TestTranslateDefaultsToBlock(t *testing.T) {
	spec := v1alpha1.AegisPolicySpec{
		Mode: "enforce",
		FileRules: &v1alpha1.FileRules{
			Deny: []v1alpha1.FileRule{{Path: "/foo"}},
		},
	}
	result, err := TranslateToINI(spec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(result.INI, "[deny_path]") {
		t.Error("rule with no action should emit as [deny_path]")
	}
	if strings.Contains(result.INI, "[allow_path]") {
		t.Error("rule with no action should not emit [allow_path]")
	}
}

func TestTranslateDeterministicOrdering(t *testing.T) {
	spec := v1alpha1.AegisPolicySpec{
		Mode: "enforce",
		FileRules: &v1alpha1.FileRules{
			Deny: []v1alpha1.FileRule{
				{Path: "/z"},
				{Path: "/a"},
				{Path: "/m"},
			},
		},
	}
	r1, _ := TranslateToINI(spec)
	r2, _ := TranslateToINI(spec)
	if r1.INI != r2.INI {
		t.Error("translator must produce byte-identical output for the same spec")
	}
	aIdx := strings.Index(r1.INI, "/a")
	mIdx := strings.Index(r1.INI, "/m")
	zIdx := strings.Index(r1.INI, "/z")
	if aIdx < 0 || mIdx < 0 || zIdx < 0 {
		t.Fatalf("missing entries: a=%d m=%d z=%d", aIdx, mIdx, zIdx)
	}
	if !(aIdx < mIdx && mIdx < zIdx) {
		t.Errorf("entries not sorted alphabetically: a=%d m=%d z=%d", aIdx, mIdx, zIdx)
	}
}

func TestMergePoliciesAllowOverridesDeny(t *testing.T) {
	// Policy A denies both /usr/bin/curl and /usr/bin/xmrig.
	denyPolicy := TranslateResult{
		INI:    "version=5\n[deny_path]\n/usr/bin/curl\n/usr/bin/xmrig\n\n",
		SHA256: "a",
	}
	// Policy B allows /usr/bin/curl. After merge, curl should disappear
	// from [deny_path] but xmrig should remain.
	allowPolicy := TranslateResult{
		INI:    "version=5\n[allow_path]\n/usr/bin/curl\n\n",
		SHA256: "b",
	}
	merged := MergePolicies([]TranslateResult{denyPolicy, allowPolicy})

	if !strings.Contains(merged.INI, "[allow_path]") {
		t.Error("merged INI missing [allow_path]")
	}
	if !strings.Contains(merged.INI, "/usr/bin/xmrig") {
		t.Error("non-overridden deny entry should remain")
	}
	// Locate the [deny_path] section and assert curl is NOT inside it.
	denyIdx := strings.Index(merged.INI, "[deny_path]")
	if denyIdx < 0 {
		t.Fatal("[deny_path] section missing — should still contain /usr/bin/xmrig")
	}
	rest := merged.INI[denyIdx:]
	nextIdx := strings.Index(rest[1:], "[")
	var denySection string
	if nextIdx == -1 {
		denySection = rest
	} else {
		denySection = rest[:nextIdx+1]
	}
	if strings.Contains(denySection, "/usr/bin/curl") {
		t.Error("/usr/bin/curl should be removed from [deny_path] when [allow_path] overrides it")
	}
}

func TestMergePoliciesAllowEmptiesSection(t *testing.T) {
	// Policy A denies /usr/bin/curl (only entry). Policy B allows it.
	// The deny_path section should disappear from the merged output.
	denyPolicy := TranslateResult{
		INI:    "version=5\n[deny_path]\n/usr/bin/curl\n\n",
		SHA256: "a",
	}
	allowPolicy := TranslateResult{
		INI:    "version=5\n[allow_path]\n/usr/bin/curl\n\n",
		SHA256: "b",
	}
	merged := MergePolicies([]TranslateResult{denyPolicy, allowPolicy})

	if strings.Contains(merged.INI, "[deny_path]") {
		t.Error("[deny_path] section should be omitted when fully overridden by [allow_path]")
	}
	if !strings.Contains(merged.INI, "[allow_path]") {
		t.Error("[allow_path] should still be present")
	}
}

func TestTranslateDenyComm(t *testing.T) {
	spec := v1alpha1.AegisPolicySpec{
		Mode: "enforce",
		ExecRules: &v1alpha1.ExecRules{
			DenyComm: []string{"xmrig", "minerd"},
		},
	}
	result, err := TranslateToINI(spec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(result.INI, "[deny_comm]") {
		t.Error("missing [deny_comm] section")
	}
	if !strings.Contains(result.INI, "xmrig") {
		t.Error("missing xmrig entry")
	}
	if !strings.Contains(result.INI, "minerd") {
		t.Error("missing minerd entry")
	}
}

func TestTranslateDenyCommSorted(t *testing.T) {
	spec := v1alpha1.AegisPolicySpec{
		Mode: "enforce",
		ExecRules: &v1alpha1.ExecRules{
			DenyComm: []string{"zzz", "aaa", "mmm"},
		},
	}
	result, _ := TranslateToINI(spec)
	aIdx := strings.Index(result.INI, "aaa")
	mIdx := strings.Index(result.INI, "mmm")
	zIdx := strings.Index(result.INI, "zzz")
	if aIdx < 0 || mIdx < 0 || zIdx < 0 {
		t.Fatal("missing entries")
	}
	if !(aIdx < mIdx && mIdx < zIdx) {
		t.Error("deny_comm entries not sorted")
	}
}

func TestTranslateDenyCommChangesHash(t *testing.T) {
	spec1 := v1alpha1.AegisPolicySpec{
		Mode: "enforce",
		ExecRules: &v1alpha1.ExecRules{
			DenyComm: []string{"xmrig"},
		},
	}
	spec2 := v1alpha1.AegisPolicySpec{
		Mode: "enforce",
		ExecRules: &v1alpha1.ExecRules{
			DenyComm: []string{"xmrig", "ethminer"},
		},
	}
	r1, _ := TranslateToINI(spec1)
	r2, _ := TranslateToINI(spec2)
	if r1.SHA256 == r2.SHA256 {
		t.Error("adding ethminer to denyComm should change the hash")
	}
}
