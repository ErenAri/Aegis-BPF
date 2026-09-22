package policy

import (
	"strings"
	"testing"

	v1alpha1 "github.com/ErenAri/aegis-operator/api/v1alpha1"
)

// TestCanonicalPortRule pins the exact encoding of the defect that motivated
// this file: the operator emitted "tcp:4444:outbound" (protocol first, CRD
// direction vocabulary) where the daemon accepts "4444:tcp:egress".
func TestCanonicalPortRule(t *testing.T) {
	cases := []struct {
		name      string
		port      int
		protocol  string
		direction string
		want      string
	}{
		{"tcp egress", 4444, "tcp", "outbound", "4444:tcp:egress"},
		{"udp egress", 5353, "udp", "outbound", "5353:udp:egress"},
		{"tcp bind", 2375, "tcp", "inbound", "2375:tcp:bind"},
		{"udp bind", 1900, "udp", "inbound", "1900:udp:bind"},
		{"both", 6667, "tcp", "both", "6667:tcp:both"},
		{"protocol any", 9001, "any", "outbound", "9001:any:egress"},
		{"default protocol", 9999, "", "outbound", "9999:tcp:egress"},
		{"default direction", 9999, "tcp", "", "9999:tcp:egress"},
		{"both defaults", 9999, "", "", "9999:tcp:egress"},
		{"lowest port", 1, "tcp", "outbound", "1:tcp:egress"},
		{"highest port", 65535, "tcp", "outbound", "65535:tcp:egress"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := CanonicalPortRule(tc.port, tc.protocol, tc.direction)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("CanonicalPortRule(%d, %q, %q) = %q, want %q",
					tc.port, tc.protocol, tc.direction, got, tc.want)
			}
		})
	}
}

// TestCanonicalPortRuleRejects proves invalid values are refused rather than
// silently becoming something else. A silently-coerced direction is how a
// Block rule turns into a rule that blocks the wrong socket operation.
func TestCanonicalPortRuleRejects(t *testing.T) {
	cases := []struct {
		name      string
		port      int
		protocol  string
		direction string
	}{
		{"port zero", 0, "tcp", "outbound"},
		{"port negative", -1, "tcp", "outbound"},
		{"port too large", 65536, "tcp", "outbound"},
		{"unknown protocol", 443, "sctp", "outbound"},
		{"daemon vocabulary is not CRD vocabulary", 443, "tcp", "egress"},
		{"unknown direction", 443, "tcp", "sideways"},
		{"uppercase protocol", 443, "TCP", "outbound"},
		{"uppercase direction", 443, "tcp", "OUTBOUND"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := CanonicalPortRule(tc.port, tc.protocol, tc.direction)
			if err == nil {
				t.Errorf("CanonicalPortRule(%d, %q, %q) = %q, want error",
					tc.port, tc.protocol, tc.direction, got)
			}
		})
	}
}

// TestCanonicalIPPortRule pins IP:PORT:PROTOCOL, including the IPv6
// bracketing the daemon's format_ip_port_rule() also produces.
func TestCanonicalIPPortRule(t *testing.T) {
	cases := []struct {
		name     string
		ip       string
		port     int
		protocol string
		want     string
	}{
		{"ipv4 tcp", "10.0.0.2", 8080, "tcp", "10.0.0.2:8080:tcp"},
		{"ipv4 udp", "10.0.0.3", 53, "udp", "10.0.0.3:53:udp"},
		{"ipv4 any", "10.0.0.4", 443, "any", "10.0.0.4:443:any"},
		{"ipv4 default protocol", "10.0.0.5", 443, "", "10.0.0.5:443:tcp"},
		{"ipv6 bracketed", "2001:db8::5", 8443, "udp", "[2001:db8::5]:8443:udp"},
		{"ipv6 loopback bracketed", "::1", 443, "tcp", "[::1]:443:tcp"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := CanonicalIPPortRule(tc.ip, tc.port, tc.protocol)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("CanonicalIPPortRule(%q, %d, %q) = %q, want %q",
					tc.ip, tc.port, tc.protocol, got, tc.want)
			}
		})
	}
}

// TestCanonicalIPPortRuleBracketsIPv6 is called out separately because an
// unbracketed IPv6 literal is not merely ugly, it is ambiguous: "::1:443"
// is itself a valid IPv6 address as well as ::1 port 443.
func TestCanonicalIPPortRuleBracketsIPv6(t *testing.T) {
	got, err := CanonicalIPPortRule("::1", 443, "tcp")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(got, "[") {
		t.Errorf("IPv6 literal %q must be bracketed to disambiguate the port separator", got)
	}
}

// TestTranslateRejectsUnsupportedDirection is the defence-in-depth check:
// the CRD enum already restricts direction to outbound|inbound, so an
// unsupported value can only arrive through CRD drift or a client that
// bypasses schema validation. When it does, translation must fail loudly
// rather than emit a rule the daemon will reject (taking the whole policy
// file down with it) or, worse, a rule that means something else.
func TestTranslateRejectsUnsupportedDirection(t *testing.T) {
	_, err := TranslateToINI(v1alpha1.AegisPolicySpec{
		Mode: "enforce",
		NetworkRules: &v1alpha1.NetworkRules{
			Deny: []v1alpha1.NetworkRule{
				{Port: 4444, Protocol: "tcp", Direction: "sideways"},
			},
		},
	})
	if err == nil {
		t.Fatal("expected translation to fail on an unsupported direction")
	}
	if !strings.Contains(err.Error(), "networkRules.deny[0]") {
		t.Errorf("error should identify the offending rule index; got %v", err)
	}
}

func TestTranslateRejectsUnsupportedProtocol(t *testing.T) {
	_, err := TranslateToINI(v1alpha1.AegisPolicySpec{
		Mode: "enforce",
		NetworkRules: &v1alpha1.NetworkRules{
			Deny: []v1alpha1.NetworkRule{
				{IP: "10.0.0.2", Port: 8080, Protocol: "sctp"},
			},
		},
	})
	if err == nil {
		t.Fatal("expected translation to fail on an unsupported protocol")
	}
}

// TestTranslateNeverEmitsUnsupportedAllowSections is a blanket guard: no
// spec shape may produce a section the daemon's valid_sections list lacks,
// because one unknown section fails the entire policy file.
func TestTranslateNeverEmitsUnsupportedAllowSections(t *testing.T) {
	allow := v1alpha1.RuleActionAllow
	spec := v1alpha1.AegisPolicySpec{
		Mode: "enforce",
		FileRules: &v1alpha1.FileRules{
			Deny: []v1alpha1.FileRule{{Path: "/usr/bin/curl", Action: allow}},
		},
		NetworkRules: &v1alpha1.NetworkRules{
			Deny: []v1alpha1.NetworkRule{
				{IP: "203.0.113.5", Action: allow},
				{CIDR: "203.0.113.0/24", Action: allow},
				{Port: 9090, Protocol: "tcp", Direction: "outbound", Action: allow},
				{IP: "203.0.113.6", Port: 8080, Protocol: "tcp", Action: allow},
			},
		},
	}
	res, err := TranslateToINI(spec)
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	for _, unsupported := range []string{
		"[allow_path]", "[allow_ip]", "[allow_cidr]", "[allow_port]", "[allow_ip_port]",
	} {
		if strings.Contains(res.INI, unsupported) {
			t.Errorf("emitted %s; src/policy_parse.cpp rejects it as an unknown section", unsupported)
		}
	}
	// The Allow intent must survive somewhere, or the merge sweep breaks.
	wantSections := []string{"deny_path", "deny_ip", "deny_cidr", "deny_port", "deny_ip_port"}
	if len(res.AllowOverrides) != len(wantSections) {
		t.Errorf("AllowOverrides = %v, want %d deny sections covered", res.AllowOverrides, len(wantSections))
	}
	for _, section := range wantSections {
		if len(res.AllowOverrides[section]) == 0 {
			t.Errorf("Allow rule for %s was lost; the merge sweep can no longer resolve it", section)
		}
	}
	if got := res.AllowOverrides["deny_port"]; len(got) != 1 || got[0] != "9090:tcp:egress" {
		t.Errorf("deny_port override = %v, want [9090:tcp:egress]", got)
	}
	if got := res.AllowOverrides["deny_ip_port"]; len(got) != 1 || got[0] != "203.0.113.6:8080:tcp" {
		t.Errorf("deny_ip_port override = %v, want [203.0.113.6:8080:tcp]", got)
	}
}
