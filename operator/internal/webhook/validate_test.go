package webhook

import (
	"testing"

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
	errs := validateSpec(spec)
	if len(errs) > 0 {
		t.Errorf("expected no errors, got: %v", errs)
	}
}

func TestValidateSpecInvalidMode(t *testing.T) {
	spec := v1alpha1.AegisPolicySpec{Mode: "invalid"}
	errs := validateSpec(spec)
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
	errs := validateSpec(spec)
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
	errs := validateSpec(spec)
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
	errs := validateSpec(spec)
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
	errs := validateSpec(spec)
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
	errs := validateSpec(spec)
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
	errs := validateSpec(spec)
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
	errs := validateSpec(spec)
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
	errs := validateSpec(spec)
	if len(errs) == 0 {
		t.Error("expected error for non-hex 64-character hash")
	}
}
