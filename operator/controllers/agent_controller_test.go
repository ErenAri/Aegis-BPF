package controllers

import (
	"testing"

	v1alpha1 "github.com/ErenAri/aegis-operator/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestPolicyRules_MainlineAgent(t *testing.T) {
	spec := v1alpha1.AegisPolicySpec{
		Mode: "enforce",
		FileRules: &v1alpha1.FileRules{
			Deny: []v1alpha1.FileRule{
				{Path: "/etc/shadow"},
				{Path: "/usr/bin/bad"},
			},
		},
		NetworkRules: &v1alpha1.NetworkRules{
			Deny: []v1alpha1.NetworkRule{
				{IP: "10.0.0.1", Action: v1alpha1.RuleActionBlock},
				{Port: 4444, Direction: "outbound", Action: v1alpha1.RuleActionBlock},
			},
		},
	}

	rules := policyRules(spec)
	if len(rules) != 4 {
		t.Fatalf("expected 4 rules, got %d", len(rules))
	}

	// Verify mainline binary path.
	for _, r := range rules {
		if r.Add[0] != AgentBinaryPath {
			t.Errorf("expected binary %s, got %s", AgentBinaryPath, r.Add[0])
		}
	}

	// Verify file rule uses "block" subcommand.
	if rules[0].Add[1] != "block" {
		t.Errorf("expected 'block', got %s", rules[0].Add[1])
	}

	// Verify network rule uses "network deny" subcommand.
	if rules[2].Add[1] != "network" {
		t.Errorf("expected 'network', got %s", rules[2].Add[1])
	}
}

func TestPolicyRulesNext_AegisNextAgent(t *testing.T) {
	spec := v1alpha1.AegisPolicySpec{
		Mode: "enforce",
		ExecRules: &v1alpha1.ExecRules{
			DenyComm: []string{"xmrig", "minerd"},
		},
		FileRules: &v1alpha1.FileRules{
			Deny: []v1alpha1.FileRule{
				{Path: "/etc/shadow"},
			},
		},
		NetworkRules: &v1alpha1.NetworkRules{
			Deny: []v1alpha1.NetworkRule{
				{Port: 4444, Direction: "outbound", Action: v1alpha1.RuleActionBlock},
				{Port: 31337, Direction: "inbound", Action: v1alpha1.RuleActionBlock},
			},
		},
	}

	rules := policyRulesNext(spec)

	// 1 file + 2 exec + 2 network = 5 rules.
	if len(rules) != 5 {
		t.Fatalf("expected 5 rules, got %d", len(rules))
	}

	// All should use aegis-next binary.
	for _, r := range rules {
		if r.Add[0] != AgentNextBinaryPath {
			t.Errorf("expected binary %s, got %s", AgentNextBinaryPath, r.Add[0])
		}
	}

	// Build a map for order-independent checks.
	ruleMap := map[string]agentRule{}
	for _, r := range rules {
		ruleMap[r.Key] = r
	}

	// Check file rules use "policy add file path".
	fileRule, ok := ruleMap["file:path:/etc/shadow"]
	if !ok {
		t.Fatal("missing file rule for /etc/shadow")
	}
	if fileRule.Add[3] != "file" {
		t.Errorf("expected 'file' in add command, got: %v", fileRule.Add)
	}

	// Check exec rules use "policy add exec comm".
	execRule, ok := ruleMap["exec:comm:xmrig"]
	if !ok {
		t.Fatal("missing exec rule for xmrig")
	}
	if execRule.Add[1] != "policy" || execRule.Add[2] != "add" || execRule.Add[3] != "exec" {
		t.Errorf("unexpected exec add command: %v", execRule.Add)
	}

	// Check outbound network uses "conn" hook.
	connRule, ok := ruleMap["net:port:4444::outbound"]
	if !ok {
		t.Fatal("missing conn rule for port 4444")
	}
	if connRule.Add[3] != "conn" {
		t.Errorf("expected 'conn' hook for outbound, got: %v", connRule.Add)
	}

	// Check inbound network uses "bind" hook.
	bindRule, ok := ruleMap["net:port:31337::inbound"]
	if !ok {
		t.Fatal("missing bind rule for port 31337")
	}
	if bindRule.Add[3] != "bind" {
		t.Errorf("expected 'bind' hook for inbound, got: %v", bindRule.Add)
	}
}

func TestPolicyRulesNext_AllowActionSkipped(t *testing.T) {
	spec := v1alpha1.AegisPolicySpec{
		Mode: "audit",
		NetworkRules: &v1alpha1.NetworkRules{
			Deny: []v1alpha1.NetworkRule{
				{Port: 80, Action: v1alpha1.RuleActionAllow},
				{Port: 4444, Action: v1alpha1.RuleActionBlock},
			},
		},
	}

	rules := policyRulesNext(spec)
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule (Allow should be skipped), got %d", len(rules))
	}
}

func TestDifference(t *testing.T) {
	left := []agentRule{
		{Key: "a"}, {Key: "b"}, {Key: "c"},
	}
	right := []agentRule{
		{Key: "b"}, {Key: "d"},
	}

	diff := difference(left, right)
	if len(diff) != 2 {
		t.Fatalf("expected 2 items in diff, got %d", len(diff))
	}
	keys := map[string]bool{}
	for _, r := range diff {
		keys[r.Key] = true
	}
	if !keys["a"] || !keys["c"] {
		t.Errorf("expected keys a and c, got %v", keys)
	}
}

func TestDedupeRules(t *testing.T) {
	rules := []agentRule{
		{Key: "a"}, {Key: "b"}, {Key: "a"}, {Key: "c"}, {Key: "b"},
	}
	deduped := dedupeRules(rules)
	if len(deduped) != 3 {
		t.Fatalf("expected 3 unique rules, got %d", len(deduped))
	}
}

func TestReplaceAgentBinary(t *testing.T) {
	cmd := []string{AgentBinaryPath, "block", "add", "/etc/shadow"}
	replaced := replaceAgentBinary(cmd, AgentNextBinaryPath)

	if replaced[0] != AgentNextBinaryPath {
		t.Errorf("expected %s, got %s", AgentNextBinaryPath, replaced[0])
	}
	// Original should be unchanged.
	if cmd[0] != AgentBinaryPath {
		t.Error("original command was mutated")
	}
	// Rest of command preserved.
	if replaced[1] != "block" || replaced[3] != "/etc/shadow" {
		t.Errorf("command args were modified: %v", replaced)
	}
}

func TestHasContainer(t *testing.T) {
	pod := &corev1.Pod{
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{Name: "aegisbpf"},
				{Name: "sidecar"},
			},
		},
	}

	if !hasContainer(pod, "aegisbpf") {
		t.Error("expected to find container 'aegisbpf'")
	}
	if hasContainer(pod, "aegisbpf-next") {
		t.Error("should not find container 'aegisbpf-next'")
	}
}

func TestAgentPodIsNext(t *testing.T) {
	tests := []struct {
		name     string
		podName  string
		containers []string
		wantNext bool
	}{
		{"mainline pod", "aegisbpf-abc123", []string{"aegisbpf"}, false},
		{"next pod by name", "aegisbpf-next-xyz", []string{"aegisbpf-next"}, true},
		{"next pod by container", "aegis-custom", []string{"aegisbpf-next", "sidecar"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: tt.podName},
				Spec: corev1.PodSpec{},
			}
			for _, c := range tt.containers {
				pod.Spec.Containers = append(pod.Spec.Containers, corev1.Container{Name: c})
			}

			isNext := containsAegisNext(tt.podName) || hasContainer(pod, AgentNextContainerName)
			if isNext != tt.wantNext {
				t.Errorf("isNext=%v, want %v", isNext, tt.wantNext)
			}
		})
	}
}

// containsAegisNext mirrors the logic in findAgentForNode.
func containsAegisNext(name string) bool {
	return len(name) >= len("aegisbpf-next") && name[:len("aegisbpf-next")] == "aegisbpf-next" ||
		len(name) > len("aegisbpf-next") && name[len(name)-len("-next"):] == "-next"
}
