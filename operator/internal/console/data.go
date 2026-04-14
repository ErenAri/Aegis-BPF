package console

import (
	"context"
	"fmt"
	"sort"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/ErenAri/aegis-operator/api/v1alpha1"
)

// PolicySummary is the view-model for a single policy in the console.
type PolicySummary struct {
	Name         string
	Namespace    string
	Scope        string // "Namespaced" or "Cluster"
	Mode         string
	Phase        string
	Message      string
	Hash         string
	AppliedNodes int
	LastApplied  *time.Time
	Generation   int64
	Conditions   []ConditionView
	FileRules    int
	NetworkRules int
	ExecRules    int
	KernelRules  int
	HasAllow     bool
	HasBlock     bool
	Deprecated   bool
}

// ConditionView is the template-friendly view of a metav1.Condition.
type ConditionView struct {
	Type    string
	Status  string
	Reason  string
	Message string
	Ago     string
}

// DashboardData is the full page data for the dashboard.
type DashboardData struct {
	Page            string // "dashboard", "policies", "nodes" — for active nav
	Policies        []PolicySummary
	TotalPolicies   int
	EnforceCount    int
	AuditCount      int
	AppliedCount    int
	ErrorCount      int
	DeprecatedCount int
	AllowRuleCount  int
	BlockRuleCount  int
	DaemonPods      []DaemonPodView
	RunningPods     int
	ActiveClients   int
	Now             time.Time
}

// DaemonPodView is the template-friendly view of an aegisbpf daemon pod.
type DaemonPodView struct {
	Name      string
	Node      string
	Phase     string
	Ready     bool
	Restarts  int32
	Age       string
	IP        string
}

// gatherDashboardData collects all data needed for the dashboard page.
func (s *Server) gatherDashboardData(ctx context.Context) DashboardData {
	policies := s.listAllPolicies(ctx)
	daemonPods := s.listDaemonPods(ctx)

	data := DashboardData{
		Policies:      policies,
		TotalPolicies: len(policies),
		DaemonPods:    daemonPods,
		ActiveClients: s.broker.ClientCount(),
		Now:           time.Now(),
	}

	for _, p := range policies {
		switch p.Mode {
		case "enforce":
			data.EnforceCount++
		case "audit":
			data.AuditCount++
		}
		switch p.Phase {
		case "Applied":
			data.AppliedCount++
		case "Error":
			data.ErrorCount++
		}
		if p.Deprecated {
			data.DeprecatedCount++
		}
		if p.HasAllow {
			data.AllowRuleCount++
		}
		if p.HasBlock {
			data.BlockRuleCount++
		}
	}

	for _, pod := range daemonPods {
		if pod.Phase == "Running" {
			data.RunningPods++
		}
	}

	return data
}

// listAllPolicies returns summaries for all AegisPolicy + AegisClusterPolicy resources.
func (s *Server) listAllPolicies(ctx context.Context) []PolicySummary {
	var summaries []PolicySummary

	// Namespaced policies.
	var nsList v1alpha1.AegisPolicyList
	if err := s.client.List(ctx, &nsList); err == nil {
		for _, p := range nsList.Items {
			summaries = append(summaries, toPolicySummary(
				p.Name, p.Namespace, "Namespaced", p.Spec, p.Status, p.Generation))
		}
	}

	// Cluster policies.
	var cList v1alpha1.AegisClusterPolicyList
	if err := s.client.List(ctx, &cList); err == nil {
		for _, p := range cList.Items {
			summaries = append(summaries, toPolicySummary(
				p.Name, "", "Cluster", p.Spec, p.Status, p.Generation))
		}
	}

	sort.Slice(summaries, func(i, j int) bool {
		if summaries[i].Scope != summaries[j].Scope {
			return summaries[i].Scope < summaries[j].Scope
		}
		if summaries[i].Namespace != summaries[j].Namespace {
			return summaries[i].Namespace < summaries[j].Namespace
		}
		return summaries[i].Name < summaries[j].Name
	})

	return summaries
}

func toPolicySummary(name, ns, scope string, spec v1alpha1.AegisPolicySpec, status v1alpha1.AegisPolicyStatus, gen int64) PolicySummary {
	ps := PolicySummary{
		Name:         name,
		Namespace:    ns,
		Scope:        scope,
		Mode:         spec.Mode,
		Phase:        status.Phase,
		Message:      status.Message,
		Hash:         status.PolicyHash,
		AppliedNodes: status.AppliedNodes,
		Generation:   gen,
	}

	if status.LastAppliedAt != nil {
		t := status.LastAppliedAt.Time
		ps.LastApplied = &t
	}

	// Count rules.
	if spec.FileRules != nil {
		ps.FileRules = len(spec.FileRules.Deny) + len(spec.FileRules.Protect)
		for _, r := range spec.FileRules.Deny {
			if r.Action == v1alpha1.RuleActionAllow {
				ps.HasAllow = true
			} else {
				ps.HasBlock = true
			}
		}
	}
	if spec.NetworkRules != nil {
		ps.NetworkRules = len(spec.NetworkRules.Deny)
		for _, r := range spec.NetworkRules.Deny {
			if r.Action == v1alpha1.RuleActionAllow {
				ps.HasAllow = true
			} else {
				ps.HasBlock = true
			}
		}
	}
	if spec.ExecRules != nil {
		ps.ExecRules = len(spec.ExecRules.AllowBinaryHashes) +
			len(spec.ExecRules.DenyBinaryHashes) +
			len(spec.ExecRules.DenyComm)
	}
	if spec.KernelRules != nil {
		count := 0
		if spec.KernelRules.BlockModuleLoad {
			count++
		}
		if spec.KernelRules.BlockPtrace {
			count++
		}
		if spec.KernelRules.BlockBpfSyscall {
			count++
		}
		ps.KernelRules = count
	}

	// Conditions.
	for _, c := range status.Conditions {
		ps.Conditions = append(ps.Conditions, toConditionView(c))
		if c.Type == "Deprecated" && c.Status == metav1.ConditionTrue {
			ps.Deprecated = true
		}
	}

	return ps
}

func toConditionView(c metav1.Condition) ConditionView {
	return ConditionView{
		Type:    c.Type,
		Status:  string(c.Status),
		Reason:  c.Reason,
		Message: c.Message,
		Ago:     timeAgoStr(c.LastTransitionTime.Time),
	}
}

func timeAgoStr(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		m := int(d.Minutes())
		if m == 1 {
			return "1m ago"
		}
		return fmt.Sprintf("%dm ago", m)
	case d < 24*time.Hour:
		h := int(d.Hours())
		if h == 1 {
			return "1h ago"
		}
		return fmt.Sprintf("%dh ago", h)
	default:
		days := int(d.Hours()) / 24
		if days == 1 {
			return "1d ago"
		}
		return fmt.Sprintf("%dd ago", days)
	}
}

// listDaemonPods returns aegisbpf daemon pods across the cluster.
func (s *Server) listDaemonPods(ctx context.Context) []DaemonPodView {
	var podList corev1.PodList
	if err := s.client.List(ctx, &podList, client.MatchingLabels{
		"app.kubernetes.io/name": "aegisbpf",
	}); err != nil {
		return nil
	}

	var pods []DaemonPodView
	for _, pod := range podList.Items {
		ready := false
		var restarts int32
		for _, cs := range pod.Status.ContainerStatuses {
			if cs.Ready {
				ready = true
			}
			restarts += cs.RestartCount
		}
		pods = append(pods, DaemonPodView{
			Name:     pod.Name,
			Node:     pod.Spec.NodeName,
			Phase:    string(pod.Status.Phase),
			Ready:    ready,
			Restarts: restarts,
			Age:      timeAgoStr(pod.CreationTimestamp.Time),
			IP:       pod.Status.PodIP,
		})
	}

	sort.Slice(pods, func(i, j int) bool {
		return pods[i].Node < pods[j].Node
	})

	return pods
}

