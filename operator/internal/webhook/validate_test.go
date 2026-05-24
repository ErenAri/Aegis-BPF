package webhook

import (
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1alpha1 "github.com/ErenAri/aegis-operator/api/v1alpha1"
)

func TestValidateSpecValid(t *testing.T) {
	spec := v1alpha1.AegisPolicySpec{
		Mode: "enforce",
		FileRules: &v1alpha1.FileRules{
			Deny: []v1alpha1.FileRule{
				{Path: "/usr/bin/xmrig"},
				{Inode: "259:12345"},
			},
		},
		NetworkRules: &v1alpha1.NetworkRules{
			Deny: []v1alpha1.NetworkRule{
				{IP: "10.0.0.1"},
				{CIDR: "192.168.0.0/16"},
				{Port: 4444, Protocol: "tcp", Direction: "outbound"},
			},
		},
		KernelRules: &v1alpha1.KernelRules{
			BlockPtrace: true,
		},
	}
	errs := validateSpec(spec, "")
	if len(errs) > 0 {
		t.Errorf("expected no errors, got: %v", errs)
	}
}

func TestValidateSpecInvalidMode(t *testing.T) {
	spec := v1alpha1.AegisPolicySpec{Mode: "invalid"}
	errs := validateSpec(spec, "")
	if len(errs) != 1 {
		t.Fatalf("expected 1 error, got %d: %v", len(errs), errs)
	}
}

func TestValidateSpecRelativePath(t *testing.T) {
	spec := v1alpha1.AegisPolicySpec{
		Mode: "enforce",
		FileRules: &v1alpha1.FileRules{
			Deny: []v1alpha1.FileRule{{Path: "relative/path"}},
		},
	}
	errs := validateSpec(spec, "")
	if len(errs) == 0 {
		t.Error("expected error for relative path")
	}
}

func TestValidateSpecEmptyFileRule(t *testing.T) {
	spec := v1alpha1.AegisPolicySpec{
		Mode: "enforce",
		FileRules: &v1alpha1.FileRules{
			Deny: []v1alpha1.FileRule{{}},
		},
	}
	errs := validateSpec(spec, "")
	if len(errs) == 0 {
		t.Error("expected error for empty file rule")
	}
}

func TestValidateSpecInvalidIP(t *testing.T) {
	spec := v1alpha1.AegisPolicySpec{
		Mode: "enforce",
		NetworkRules: &v1alpha1.NetworkRules{
			Deny: []v1alpha1.NetworkRule{{IP: "not-an-ip"}},
		},
	}
	errs := validateSpec(spec, "")
	if len(errs) == 0 {
		t.Error("expected error for invalid IP")
	}
}

func TestValidateSpecInvalidCIDR(t *testing.T) {
	spec := v1alpha1.AegisPolicySpec{
		Mode: "enforce",
		NetworkRules: &v1alpha1.NetworkRules{
			Deny: []v1alpha1.NetworkRule{{CIDR: "invalid/cidr"}},
		},
	}
	errs := validateSpec(spec, "")
	if len(errs) == 0 {
		t.Error("expected error for invalid CIDR")
	}
}

func TestValidateSpecEmptyNetworkRule(t *testing.T) {
	spec := v1alpha1.AegisPolicySpec{
		Mode: "enforce",
		NetworkRules: &v1alpha1.NetworkRules{
			Deny: []v1alpha1.NetworkRule{{}},
		},
	}
	errs := validateSpec(spec, "")
	if len(errs) == 0 {
		t.Error("expected error for empty network rule")
	}
}

func TestValidateSpecBadHash(t *testing.T) {
	spec := v1alpha1.AegisPolicySpec{
		Mode: "enforce",
		ExecRules: &v1alpha1.ExecRules{
			AllowBinaryHashes: []string{"tooshort"},
		},
	}
	errs := validateSpec(spec, "")
	if len(errs) == 0 {
		t.Error("expected error for short hash")
	}
}

func TestValidateSpecValidHash(t *testing.T) {
	spec := v1alpha1.AegisPolicySpec{
		Mode: "enforce",
		ExecRules: &v1alpha1.ExecRules{
			AllowBinaryHashes: []string{"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
		},
	}
	errs := validateSpec(spec, "")
	if len(errs) > 0 {
		t.Errorf("expected no errors, got: %v", errs)
	}
}

func TestValidateSpecNonHex64CharHash(t *testing.T) {
	// 64 characters long but contains non-hex character 'g'
	nonHexHash := "gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg"

	spec := v1alpha1.AegisPolicySpec{
		Mode: "enforce",
		ExecRules: &v1alpha1.ExecRules{
			AllowBinaryHashes: []string{nonHexHash},
		},
	}
	errs := validateSpec(spec, "")
	if len(errs) == 0 {
		t.Error("expected error for non-hex 64-character hash")
	}
}

// --- v0.5.0: per-rule action collisions ----------------------------------

func TestValidateRejectsAllowOnInodeRule(t *testing.T) {
	spec := v1alpha1.AegisPolicySpec{
		Mode: "enforce",
		FileRules: &v1alpha1.FileRules{
			Deny: []v1alpha1.FileRule{
				{Inode: "259:12345", Action: v1alpha1.RuleActionAllow},
			},
		},
	}
	errs := validateSpec(spec, "")
	if len(errs) == 0 {
		t.Fatal("expected error for Action=Allow on inode rule")
	}
	if !strings.Contains(errs[0], "inode") {
		t.Errorf("expected error to mention inode, got: %v", errs[0])
	}
}

func TestValidateRejectsAllowOnProtectRule(t *testing.T) {
	spec := v1alpha1.AegisPolicySpec{
		Mode: "enforce",
		FileRules: &v1alpha1.FileRules{
			Protect: []v1alpha1.FileRule{
				{Path: "/etc/shadow", Action: v1alpha1.RuleActionAllow},
			},
		},
	}
	errs := validateSpec(spec, "")
	if len(errs) == 0 {
		t.Fatal("expected error for Action=Allow on protect rule")
	}
}

func TestValidateRejectsFilePathAllowBlockCollision(t *testing.T) {
	spec := v1alpha1.AegisPolicySpec{
		Mode: "enforce",
		FileRules: &v1alpha1.FileRules{
			Deny: []v1alpha1.FileRule{
				{Path: "/usr/bin/curl", Action: v1alpha1.RuleActionAllow},
				{Path: "/usr/bin/curl", Action: v1alpha1.RuleActionBlock},
			},
		},
	}
	errs := validateSpec(spec, "")
	if len(errs) == 0 {
		t.Fatal("expected collision error for same path with Allow and Block")
	}
	found := false
	for _, e := range errs {
		if strings.Contains(e, "/usr/bin/curl") && strings.Contains(e, "Allow") && strings.Contains(e, "Block") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected collision error mentioning the path, got: %v", errs)
	}
}

func TestValidateRejectsNetworkAllowBlockCollision(t *testing.T) {
	spec := v1alpha1.AegisPolicySpec{
		Mode: "enforce",
		NetworkRules: &v1alpha1.NetworkRules{
			Deny: []v1alpha1.NetworkRule{
				{IP: "10.0.0.1", Action: v1alpha1.RuleActionAllow},
				{IP: "10.0.0.1", Action: v1alpha1.RuleActionBlock},
			},
		},
	}
	errs := validateSpec(spec, "")
	if len(errs) == 0 {
		t.Fatal("expected collision error for same IP with Allow and Block")
	}
}

func TestValidateRejectsExecHashAllowBlockCollision(t *testing.T) {
	hash := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	spec := v1alpha1.AegisPolicySpec{
		Mode: "enforce",
		ExecRules: &v1alpha1.ExecRules{
			AllowBinaryHashes: []string{hash},
			DenyBinaryHashes:  []string{hash},
		},
	}
	errs := validateSpec(spec, "")
	if len(errs) == 0 {
		t.Fatal("expected collision error for same hash in allow+deny")
	}
}

// --- v0.5.0: WorkloadSelector validation ---------------------------------

func TestValidateWorkloadSelectorAccepted(t *testing.T) {
	spec := v1alpha1.AegisPolicySpec{
		Mode: "enforce",
		WorkloadSelector: &v1alpha1.WorkloadSelector{
			PodSelector: &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{Key: "tier", Operator: metav1.LabelSelectorOpIn, Values: []string{"frontend"}},
				},
			},
		},
	}
	errs := validateSpec(spec, "default")
	if len(errs) > 0 {
		t.Errorf("expected no errors, got: %v", errs)
	}
}

func TestValidateWorkloadSelectorInvalidExpression(t *testing.T) {
	spec := v1alpha1.AegisPolicySpec{
		Mode: "enforce",
		WorkloadSelector: &v1alpha1.WorkloadSelector{
			PodSelector: &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					// Operator=In requires non-empty values.
					{Key: "tier", Operator: metav1.LabelSelectorOpIn, Values: []string{}},
				},
			},
		},
	}
	errs := validateSpec(spec, "")
	if len(errs) == 0 {
		t.Fatal("expected error for invalid LabelSelector requirement")
	}
}

func TestValidateNamespacedPolicyRejectsCrossNamespace(t *testing.T) {
	spec := v1alpha1.AegisPolicySpec{
		Mode: "enforce",
		WorkloadSelector: &v1alpha1.WorkloadSelector{
			MatchNamespaceNames: []string{"other"},
		},
	}
	errs := validateSpec(spec, "default")
	if len(errs) == 0 {
		t.Fatal("expected error for namespaced policy targeting another namespace")
	}
}

func TestValidateNamespacedPolicyAllowsOwnNamespace(t *testing.T) {
	spec := v1alpha1.AegisPolicySpec{
		Mode: "enforce",
		WorkloadSelector: &v1alpha1.WorkloadSelector{
			MatchNamespaceNames: []string{"default"},
		},
	}
	errs := validateSpec(spec, "default")
	if len(errs) > 0 {
		t.Errorf("policy referencing its own namespace should pass, got: %v", errs)
	}
}

func TestValidateNamespacedPolicyAllowsPinnedNamespaceSelector(t *testing.T) {
	spec := v1alpha1.AegisPolicySpec{
		Mode: "enforce",
		WorkloadSelector: &v1alpha1.WorkloadSelector{
			NamespaceSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"kubernetes.io/metadata.name": "default"},
			},
		},
	}
	errs := validateSpec(spec, "default")
	if len(errs) > 0 {
		t.Errorf("namespaceSelector pinned to own namespace should pass, got: %v", errs)
	}
}

func TestValidateClusterPolicyAllowsCrossNamespaceSelector(t *testing.T) {
	spec := v1alpha1.AegisPolicySpec{
		Mode: "enforce",
		WorkloadSelector: &v1alpha1.WorkloadSelector{
			MatchNamespaceNames: []string{"prod", "staging"},
		},
	}
	// ownNS == "" → cluster-scoped resource, no scope check.
	errs := validateSpec(spec, "")
	if len(errs) > 0 {
		t.Errorf("cluster policy should accept cross-namespace selectors, got: %v", errs)
	}
}

// --- v0.6.0: denyComm validation -----------------------------------------

func TestValidateDenyCommValid(t *testing.T) {
	spec := v1alpha1.AegisPolicySpec{
		Mode: "enforce",
		ExecRules: &v1alpha1.ExecRules{
			DenyComm: []string{"xmrig", "minerd", "bash"},
		},
	}
	errs := validateSpec(spec, "")
	if len(errs) > 0 {
		t.Errorf("expected no errors, got: %v", errs)
	}
}

func TestValidateDenyCommTooLong(t *testing.T) {
	spec := v1alpha1.AegisPolicySpec{
		Mode: "enforce",
		ExecRules: &v1alpha1.ExecRules{
			DenyComm: []string{"this-name-is-way-too-long"},
		},
	}
	errs := validateSpec(spec, "")
	if len(errs) == 0 {
		t.Fatal("expected error for comm exceeding 15 chars")
	}
	if !strings.Contains(errs[0], "15 chars") {
		t.Errorf("expected error about 15 chars, got: %v", errs[0])
	}
}

func TestValidateDenyCommEmpty(t *testing.T) {
	spec := v1alpha1.AegisPolicySpec{
		Mode: "enforce",
		ExecRules: &v1alpha1.ExecRules{
			DenyComm: []string{""},
		},
	}
	errs := validateSpec(spec, "")
	if len(errs) == 0 {
		t.Fatal("expected error for empty comm")
	}
}

func TestValidateDenyCommSlash(t *testing.T) {
	spec := v1alpha1.AegisPolicySpec{
		Mode: "enforce",
		ExecRules: &v1alpha1.ExecRules{
			DenyComm: []string{"/usr/bin/xmrig"},
		},
	}
	errs := validateSpec(spec, "")
	found := false
	for _, e := range errs {
		if strings.Contains(e, "must not contain '/'") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected error about slash, got: %v", errs)
	}
}

func TestValidateDenyCommExactly15(t *testing.T) {
	// 15 chars is the max — should pass.
	spec := v1alpha1.AegisPolicySpec{
		Mode: "enforce",
		ExecRules: &v1alpha1.ExecRules{
			DenyComm: []string{"123456789012345"},
		},
	}
	errs := validateSpec(spec, "")
	if len(errs) > 0 {
		t.Errorf("15-char comm should be valid, got: %v", errs)
	}
}

func TestValidateRejectsInvalidNamespaceName(t *testing.T) {
	spec := v1alpha1.AegisPolicySpec{
		Mode: "enforce",
		WorkloadSelector: &v1alpha1.WorkloadSelector{
			MatchNamespaceNames: []string{"NotAValidNS!"},
		},
	}
	errs := validateSpec(spec, "")
	if len(errs) == 0 {
		t.Fatal("expected error for invalid DNS-1123 namespace name")
	}
}
