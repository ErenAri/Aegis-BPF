package policy

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	v1alpha1 "github.com/ErenAri/aegis-operator/api/v1alpha1"
)

// This file is the cross-component contract between the Kubernetes operator
// and the Aegis daemon.
//
// It exists because the defect it guards against — the operator emitting
// "tcp:4444:outbound" while src/policy_parse.cpp only accepts
// "4444:tcp:egress" — survived a full unit-test suite that asserted
// `strings.Contains(result.INI, "10.0.0.2:tcp:8080:outbound")`. That test
// proved the translator generated the string it was written to generate. It
// could not fail, because nothing in it consulted the consumer.
//
// So these tests deliberately do NOT reimplement the grammar in Go. They
// hand the generated policy to the real `aegisbpf policy validate`
// subcommand, which runs the shipped parse_policy_file() in
// src/policy_parse.cpp, and assert on its exit status.
//
// LIMITATIONS, stated plainly:
//
//   - This verifies PARSER ACCEPTANCE ONLY. It proves the daemon can read
//     and validate what the operator wrote. It does NOT prove the resulting
//     rules are installed into BPF maps, and it does NOT prove the kernel
//     enforces them. Those need root and a BPF-LSM host.
//   - It needs the daemon binary. When absent the tests skip, which means a
//     job that never builds the daemon gets no protection at all — exactly
//     the "test that cannot fail" trap above. Set
//     AEGISBPF_REQUIRE_CONTRACT_TEST=1 (CI does) to turn a missing binary
//     into a failure instead of a skip.

// daemonBinary locates the aegisbpf binary that owns the real parser.
func daemonBinary(t *testing.T) string {
	t.Helper()

	if bin := os.Getenv("AEGISBPF_BIN"); bin != "" {
		if _, err := os.Stat(bin); err != nil {
			t.Fatalf("AEGISBPF_BIN=%s is set but unusable: %v", bin, err)
		}
		return bin
	}

	// operator/internal/policy -> repository root.
	candidate, err := filepath.Abs(filepath.Join("..", "..", "..", "build", "aegisbpf"))
	if err == nil {
		if _, statErr := os.Stat(candidate); statErr == nil {
			return candidate
		}
	}

	msg := "aegisbpf binary not found; build it with " +
		"`cmake -S . -B build -G Ninja -DSKIP_BPF_BUILD=ON && cmake --build build --target aegisbpf` " +
		"or set AEGISBPF_BIN"
	if os.Getenv("AEGISBPF_REQUIRE_CONTRACT_TEST") != "" {
		t.Fatalf("AEGISBPF_REQUIRE_CONTRACT_TEST is set: %s", msg)
	}
	t.Skip(msg)
	return ""
}

// validatePolicy runs the real daemon parser over ini and reports whether it
// was accepted, along with the diagnostics the daemon printed.
func validatePolicy(t *testing.T, ini string) (bool, string) {
	t.Helper()

	bin := daemonBinary(t)
	path := filepath.Join(t.TempDir(), "generated.conf")
	if err := os.WriteFile(path, []byte(ini), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	out, err := exec.Command(bin, "policy", "validate", path).CombinedOutput()
	if err == nil {
		return true, string(out)
	}
	var exitErr *exec.ExitError
	if ok := asExitError(err, &exitErr); ok {
		return false, string(out)
	}
	t.Fatalf("running %s policy validate: %v\n%s", bin, err, out)
	return false, ""
}

func asExitError(err error, target **exec.ExitError) bool {
	if e, ok := err.(*exec.ExitError); ok {
		*target = e
		return true
	}
	return false
}

// mustTranslate translates a spec and fails the test on a translation error.
func mustTranslate(t *testing.T, spec v1alpha1.AegisPolicySpec) TranslateResult {
	t.Helper()
	res, err := TranslateToINI(spec)
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	return res
}

func netSpec(rules ...v1alpha1.NetworkRule) v1alpha1.AegisPolicySpec {
	return v1alpha1.AegisPolicySpec{
		Mode:         "enforce",
		NetworkRules: &v1alpha1.NetworkRules{Deny: rules},
	}
}

// TestContractDaemonRejectsPreFixOperatorOutput is the negative control.
//
// It pins the exact bytes the operator used to emit and asserts the daemon
// still rejects them. Two jobs: it documents the defect, and it proves this
// harness can actually observe a failure. If this test ever passes-by-
// accepting, the validator wiring is broken and every positive case below
// is meaningless.
func TestContractDaemonRejectsPreFixOperatorOutput(t *testing.T) {
	preFix := strings.Join([]string{
		"version=5",
		"# mode=enforce",
		"",
		"[deny_port]",
		"tcp:4444:outbound",
		"",
		"[deny_ip_port]",
		"10.0.0.2:tcp:8080:outbound",
		"",
	}, "\n")

	ok, out := validatePolicy(t, preFix)
	if ok {
		t.Fatalf("daemon accepted the pre-fix operator format; this harness "+
			"cannot detect the very defect it guards against.\n%s", out)
	}
	for _, want := range []string{"tcp:4444:outbound", "10.0.0.2:tcp:8080:outbound"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected daemon to name the rejected rule %q in its diagnostics; got:\n%s", want, out)
		}
	}
}

// TestContractGeneratedPolicyIsAcceptedByDaemon is the round-trip:
// AegisPolicy -> translator -> INI -> real parser -> accepted.
func TestContractGeneratedPolicyIsAcceptedByDaemon(t *testing.T) {
	allow := v1alpha1.RuleActionAllow
	block := v1alpha1.RuleActionBlock

	cases := []struct {
		name string
		spec v1alpha1.AegisPolicySpec
		// want is a literal that must appear in the generated INI, to pin
		// the canonical encoding as well as its acceptance.
		want string
	}{
		{"deny IP", netSpec(v1alpha1.NetworkRule{IP: "192.0.2.10"}), "192.0.2.10"},
		{"deny IPv6", netSpec(v1alpha1.NetworkRule{IP: "2001:db8::1"}), "2001:db8::1"},
		{"deny CIDR", netSpec(v1alpha1.NetworkRule{CIDR: "198.51.100.0/24"}), "198.51.100.0/24"},
		{"deny CIDR v6", netSpec(v1alpha1.NetworkRule{CIDR: "2001:db8:abcd::/48"}), "2001:db8:abcd::/48"},

		{"deny port TCP egress", netSpec(v1alpha1.NetworkRule{Port: 4444, Protocol: "tcp", Direction: "outbound"}), "4444:tcp:egress"},
		{"deny port UDP egress", netSpec(v1alpha1.NetworkRule{Port: 5353, Protocol: "udp", Direction: "outbound"}), "5353:udp:egress"},
		{"deny port TCP bind", netSpec(v1alpha1.NetworkRule{Port: 2375, Protocol: "tcp", Direction: "inbound"}), "2375:tcp:bind"},
		{"deny port UDP bind", netSpec(v1alpha1.NetworkRule{Port: 1900, Protocol: "udp", Direction: "inbound"}), "1900:udp:bind"},
		{"deny port both", netSpec(v1alpha1.NetworkRule{Port: 6667, Protocol: "tcp", Direction: "both"}), "6667:tcp:both"},
		{"deny port protocol any", netSpec(v1alpha1.NetworkRule{Port: 9001, Protocol: "any", Direction: "outbound"}), "9001:any:egress"},
		{"deny port defaults", netSpec(v1alpha1.NetworkRule{Port: 9999}), "9999:tcp:egress"},

		{"deny IP:port", netSpec(v1alpha1.NetworkRule{IP: "10.0.0.2", Port: 8080, Protocol: "tcp", Direction: "outbound"}), "10.0.0.2:8080:tcp"},
		{"deny IP:port UDP", netSpec(v1alpha1.NetworkRule{IP: "10.0.0.3", Port: 53, Protocol: "udp"}), "10.0.0.3:53:udp"},
		{"deny IPv6:port bracketed", netSpec(v1alpha1.NetworkRule{IP: "2001:db8::5", Port: 8443, Protocol: "udp"}), "[2001:db8::5]:8443:udp"},
		{"deny IP:port defaults", netSpec(v1alpha1.NetworkRule{IP: "10.0.0.4", Port: 443}), "10.0.0.4:443:tcp"},

		{"explicit block action", netSpec(v1alpha1.NetworkRule{Port: 23, Protocol: "tcp", Direction: "outbound", Action: block}), "23:tcp:egress"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			res := mustTranslate(t, tc.spec)
			if tc.want != "" && !strings.Contains(res.INI, tc.want) {
				t.Errorf("generated INI missing %q:\n%s", tc.want, res.INI)
			}
			ok, out := validatePolicy(t, res.INI)
			if !ok {
				t.Fatalf("daemon rejected operator-generated policy:\n--- INI ---\n%s\n--- daemon ---\n%s", res.INI, out)
			}
		})
	}

	// Allow rules: the daemon has no [allow_*] network sections, so an
	// Allow rule must leave a policy the daemon still accepts.
	allowCases := []struct {
		name string
		rule v1alpha1.NetworkRule
	}{
		{"allow IP", v1alpha1.NetworkRule{IP: "203.0.113.5", Action: allow}},
		{"allow CIDR", v1alpha1.NetworkRule{CIDR: "203.0.113.0/24", Action: allow}},
		{"allow port", v1alpha1.NetworkRule{Port: 9090, Protocol: "tcp", Direction: "outbound", Action: allow}},
		{"allow IP:port", v1alpha1.NetworkRule{IP: "203.0.113.6", Port: 8080, Protocol: "tcp", Action: allow}},
	}
	for _, tc := range allowCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			res := mustTranslate(t, netSpec(tc.rule))
			for _, unsupported := range []string{"[allow_ip]", "[allow_cidr]", "[allow_port]", "[allow_ip_port]", "[allow_path]"} {
				if strings.Contains(res.INI, unsupported) {
					t.Errorf("generated %s, which the daemon rejects as an unknown section", unsupported)
				}
			}
			ok, out := validatePolicy(t, res.INI)
			if !ok {
				t.Fatalf("daemon rejected policy containing an Allow rule:\n--- INI ---\n%s\n--- daemon ---\n%s", res.INI, out)
			}
		})
	}
}

// TestContractFullSpecIsAcceptedByDaemon exercises every section the
// translator can emit at once — file, network, exec and kernel — so a
// regression in any one of them fails here, not only in the network path.
func TestContractFullSpecIsAcceptedByDaemon(t *testing.T) {
	spec := v1alpha1.AegisPolicySpec{
		Mode: "enforce",
		FileRules: &v1alpha1.FileRules{
			Deny: []v1alpha1.FileRule{
				{Path: "/usr/bin/xmrig"},
				{Path: "/usr/bin/curl", Action: v1alpha1.RuleActionAllow},
			},
			Protect: []v1alpha1.FileRule{{Path: "/etc/shadow"}},
		},
		NetworkRules: &v1alpha1.NetworkRules{
			Deny: []v1alpha1.NetworkRule{
				{IP: "192.0.2.10"},
				{CIDR: "198.51.100.0/24"},
				{Port: 4444, Protocol: "tcp", Direction: "outbound"},
				{Port: 2375, Protocol: "tcp", Direction: "inbound"},
				{IP: "10.0.0.2", Port: 8080, Protocol: "tcp"},
				{IP: "2001:db8::5", Port: 8443, Protocol: "udp"},
			},
		},
		ExecRules: &v1alpha1.ExecRules{
			DenyComm: []string{"nc"},
			DenyBinaryHashes: []string{
				"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			},
		},
		KernelRules: &v1alpha1.KernelRules{
			BlockPtrace:     true,
			BlockModuleLoad: true,
			BlockBpfSyscall: true,
		},
	}

	res := mustTranslate(t, spec)
	if ok, out := validatePolicy(t, res.INI); !ok {
		t.Fatalf("daemon rejected full generated policy:\n--- INI ---\n%s\n--- daemon ---\n%s", res.INI, out)
	}
}

// TestContractMergedPolicyIsAcceptedByDaemon covers the other artefact the
// operator ships: the merged ConfigMap written by merged_policy_controller.
func TestContractMergedPolicyIsAcceptedByDaemon(t *testing.T) {
	blockPort := mustTranslate(t, netSpec(
		v1alpha1.NetworkRule{Port: 4444, Protocol: "tcp", Direction: "outbound"},
		v1alpha1.NetworkRule{Port: 6667, Protocol: "tcp", Direction: "outbound"},
	))
	allowPort := mustTranslate(t, netSpec(
		v1alpha1.NetworkRule{Port: 4444, Protocol: "tcp", Direction: "outbound", Action: v1alpha1.RuleActionAllow},
	))

	merged := MergePolicies([]TranslateResult{blockPort, allowPort})

	if strings.Contains(merged.INI, "4444:tcp:egress") {
		t.Error("Allow rule should have removed 4444:tcp:egress from the merged policy")
	}
	if !strings.Contains(merged.INI, "6667:tcp:egress") {
		t.Error("unrelated deny rule should survive the merge")
	}
	if ok, out := validatePolicy(t, merged.INI); !ok {
		t.Fatalf("daemon rejected merged policy:\n--- INI ---\n%s\n--- daemon ---\n%s", merged.INI, out)
	}
}

// TestContractMalformedRuleIsRejected proves the daemon still refuses
// genuinely invalid input, so "accepted" above means something. These are
// shapes the translator cannot produce; they guard the parser itself
// against being loosened to accommodate a buggy producer.
func TestContractMalformedRuleIsRejected(t *testing.T) {
	cases := []struct {
		name string
		ini  string
	}{
		{"port out of range", "version=5\n[deny_port]\n70000:tcp:egress\n"},
		{"port zero", "version=5\n[deny_port]\n0:tcp:egress\n"},
		{"unknown protocol", "version=5\n[deny_port]\n443:sctp:egress\n"},
		{"unknown direction", "version=5\n[deny_port]\n443:tcp:sideways\n"},
		{"crd direction vocabulary", "version=5\n[deny_port]\n443:tcp:outbound\n"},
		{"reversed field order", "version=5\n[deny_port]\ntcp:443:egress\n"},
		{"unknown section", "version=5\n[allow_port]\n443:tcp:egress\n"},
		{"ip_port with direction", "version=5\n[deny_ip_port]\n10.0.0.2:8080:tcp:egress\n"},
		{"ip_port bad address", "version=5\n[deny_ip_port]\n999.1.1.1:8080:tcp\n"},
		{"unbracketed ipv6 ambiguity", "version=5\n[deny_ip_port]\n[2001:db8::5]:8443:sctp\n"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if ok, out := validatePolicy(t, tc.ini); ok {
				t.Errorf("daemon accepted malformed policy %q:\n%s", tc.ini, out)
			}
		})
	}
}
