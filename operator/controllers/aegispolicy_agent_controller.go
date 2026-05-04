package controllers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	v1alpha1 "github.com/ErenAri/aegis-operator/api/v1alpha1"
)

const (
	DefaultAgentNamespace      = "aegisbpf"
	AgentContainerName         = "aegisbpf"
	AgentBinaryPath            = "/usr/bin/aegisbpf"
	AgentSyncInterval          = 30 * time.Second
	AgentSyncFinalizer         = "aegisbpf.io/agent-sync-finalizer"
	AgentStatePrefix           = "aegis-agent-state-"
	AgentAggregateStateName    = "__namespace-aggregate"
	PolicyPriorityAnnotation   = "aegisbpf.io/priority"
	ReasonAgentSyncFailed      = "AgentSyncFailed"
	ReasonAgentSynced          = "AgentSynced"
)

type agentRule struct {
	Key      string   `json:"key"`
	Add      []string `json:"add"`
	Del      []string `json:"del"`
	Source   string   `json:"source,omitempty"`
	Priority int      `json:"priority,omitempty"`
	Action   string   `json:"action,omitempty"`
}

type agentState struct {
	Nodes map[string][]agentRule `json:"nodes"`
}

type agentSyncResult struct {
	AppliedNodes int
	FailedNodes  []string
}

type policyDecision struct {
	Key      string
	Rule     agentRule
	Action   v1alpha1.RuleAction
	Priority int
	Source   string
}

// AegisPolicyAgentReconciler continuously applies namespaced AegisPolicy
// resources to the AegisBPF DaemonSet pods that run on matching workload nodes.
//
// It builds a namespace-level aggregate from all AegisPolicy resources, resolves
// duplicate targets deterministically using aegisbpf.io/priority, and persists
// the last applied per-node rule set in a controller-owned ConfigMap.
type AegisPolicyAgentReconciler struct {
	client.Client
	Scheme     *runtime.Scheme
	RestConfig *rest.Config
}

// +kubebuilder:rbac:groups=aegisbpf.io,resources=aegispolicies,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=aegisbpf.io,resources=aegispolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=aegisbpf.io,resources=aegispolicies/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=pods/exec,verbs=create
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=namespaces,verbs=get;list;create

func (r *AegisPolicyAgentReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx).WithName("agent-sync")

	var ap v1alpha1.AegisPolicy
	if err := r.Get(ctx, req.NamespacedName, &ap); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	clientset, err := kubernetes.NewForConfig(r.RestConfig)
	if err != nil {
		return ctrl.Result{}, err
	}

	if !ap.DeletionTimestamp.IsZero() {
		if controllerutil.ContainsFinalizer(&ap, AgentSyncFinalizer) {
			desired, _, err := r.aggregateDesiredAgentRules(ctx, ap.Namespace, &ap)
			if err != nil {
				_ = r.updateAgentSyncStatus(ctx, &ap, "Error", fmt.Sprintf("Agent cleanup aggregation failed: %v", err), 0, true)
				return ctrl.Result{RequeueAfter: AgentSyncInterval}, err
			}
			if _, err := r.reconcileAgentRules(ctx, clientset, ap.Namespace, AgentAggregateStateName, desired); err != nil {
				_ = r.updateAgentSyncStatus(ctx, &ap, "Error", fmt.Sprintf("Agent cleanup failed: %v", err), 0, true)
				return ctrl.Result{RequeueAfter: AgentSyncInterval}, err
			}
			controllerutil.RemoveFinalizer(&ap, AgentSyncFinalizer)
			if err := r.Update(ctx, &ap); err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
	}

	if !controllerutil.ContainsFinalizer(&ap, AgentSyncFinalizer) {
		controllerutil.AddFinalizer(&ap, AgentSyncFinalizer)
		if err := r.Update(ctx, &ap); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil
	}

	desired, ruleCount, err := r.aggregateDesiredAgentRules(ctx, ap.Namespace, nil)
	if err != nil {
		logger.Error(err, "namespace policy aggregation failed")
		_ = r.updateAgentSyncStatus(ctx, &ap, "Error", fmt.Sprintf("Policy aggregation failed: %v", err), 0, true)
		return ctrl.Result{RequeueAfter: AgentSyncInterval}, nil
	}

	if ruleCount == 0 || len(desired) == 0 {
		result, err := r.reconcileAgentRules(ctx, clientset, ap.Namespace, AgentAggregateStateName, map[string][]agentRule{})
		if err != nil {
			_ = r.updateAgentSyncStatus(ctx, &ap, "Error", fmt.Sprintf("Agent cleanup reconcile failed: %v", err), result.AppliedNodes, true)
			return ctrl.Result{RequeueAfter: AgentSyncInterval}, err
		}
		message := "No matching running workloads or no live-agent rules; stale namespace aggregate rules cleaned up"
		logger.Info(message, "policy", ap.Name)
		_ = r.updateAgentSyncStatus(ctx, &ap, "Applied", message, result.AppliedNodes, false)
		return ctrl.Result{RequeueAfter: AgentSyncInterval}, nil
	}

	result, err := r.reconcileAgentRules(ctx, clientset, ap.Namespace, AgentAggregateStateName, desired)
	if err != nil {
		message := fmt.Sprintf("Agent sync failed after %d/%d nodes: %v", result.AppliedNodes, len(desired), err)
		_ = r.updateAgentSyncStatus(ctx, &ap, "Error", message, result.AppliedNodes, true)
		return ctrl.Result{RequeueAfter: AgentSyncInterval}, err
	}

	message := fmt.Sprintf("Namespace aggregate synced to %d node(s), %d resolved rule(s); priority annotation=%s", result.AppliedNodes, ruleCount, PolicyPriorityAnnotation)
	logger.Info("namespace policy aggregate reconciled", "policy", ap.Name, "nodes", len(desired), "rules", ruleCount)
	_ = r.updateAgentSyncStatus(ctx, &ap, "Applied", message, result.AppliedNodes, false)
	return ctrl.Result{RequeueAfter: AgentSyncInterval}, nil
}

func (r *AegisPolicyAgentReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("aegispolicy-agent-sync").
		For(&v1alpha1.AegisPolicy{}).
		Complete(r)
}

func (r *AegisPolicyAgentReconciler) aggregateDesiredAgentRules(ctx context.Context, namespace string, exclude *v1alpha1.AegisPolicy) (map[string][]agentRule, int, error) {
	var policies v1alpha1.AegisPolicyList
	if err := r.List(ctx, &policies, client.InNamespace(namespace)); err != nil {
		return nil, 0, err
	}

	nodeDecisions := map[string]map[string]policyDecision{}
	for i := range policies.Items {
		policy := policies.Items[i]
		if !policy.DeletionTimestamp.IsZero() {
			continue
		}
		if exclude != nil && policy.Namespace == exclude.Namespace && policy.Name == exclude.Name {
			continue
		}

		selector, err := podSelectorForPolicy(&policy)
		if err != nil {
			return nil, 0, fmt.Errorf("policy %s/%s selector: %w", policy.Namespace, policy.Name, err)
		}

		var pods corev1.PodList
		if err := r.List(ctx, &pods, client.InNamespace(policy.Namespace), client.MatchingLabelsSelector{Selector: selector}); err != nil {
			return nil, 0, err
		}

		nodes := sets.New[string]()
		for _, pod := range pods.Items {
			if pod.Spec.NodeName != "" && pod.Status.Phase == corev1.PodRunning {
				nodes.Insert(pod.Spec.NodeName)
			}
		}
		if nodes.Len() == 0 {
			continue
		}

		priority := policyPriority(policy)
		decisions := policyDecisions(policy.Spec, policy.Namespace+"/"+policy.Name, priority)
		for _, node := range nodes.UnsortedList() {
			if nodeDecisions[node] == nil {
				nodeDecisions[node] = map[string]policyDecision{}
			}
			for _, decision := range decisions {
				current, ok := nodeDecisions[node][decision.Key]
				if !ok || decisionWins(decision, current) {
					nodeDecisions[node][decision.Key] = decision
				}
			}
		}
	}

	desired := map[string][]agentRule{}
	resolvedRules := 0
	for node, decisions := range nodeDecisions {
		keys := make([]string, 0, len(decisions))
		for key := range decisions {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			decision := decisions[key]
			if decision.Action != v1alpha1.RuleActionBlock {
				continue
			}
			rule := decision.Rule
			rule.Source = decision.Source
			rule.Priority = decision.Priority
			rule.Action = string(decision.Action)
			desired[node] = append(desired[node], rule)
			resolvedRules++
		}
	}
	return desired, resolvedRules, nil
}

func decisionWins(candidate, current policyDecision) bool {
	if candidate.Priority != current.Priority {
		return candidate.Priority > current.Priority
	}
	if candidate.Action != current.Action {
		return candidate.Action == v1alpha1.RuleActionAllow
	}
	return candidate.Source < current.Source
}

func policyPriority(policy v1alpha1.AegisPolicy) int {
	if policy.Annotations == nil {
		return 0
	}
	raw := strings.TrimSpace(policy.Annotations[PolicyPriorityAnnotation])
	if raw == "" {
		return 0
	}
	priority, err := strconv.Atoi(raw)
	if err != nil {
		return 0
	}
	return priority
}

func (r *AegisPolicyAgentReconciler) reconcileAgentRules(ctx context.Context, clientset *kubernetes.Clientset, namespace, name string, desired map[string][]agentRule) (agentSyncResult, error) {
	result := agentSyncResult{}
	current, err := r.loadAgentState(ctx, namespace, name)
	if err != nil {
		return result, err
	}

	failed := sets.New[string]()
	for node, applied := range current.Nodes {
		desiredForNode := desired[node]
		for _, stale := range difference(applied, desiredForNode) {
			agent, err := r.findAgentForNode(ctx, node)
			if err != nil {
				failed.Insert(node)
				continue
			}
			if err := r.execAgentCommand(ctx, clientset, agent, stale.Del); err != nil {
				failed.Insert(node)
				continue
			}
		}
	}

	for node, wanted := range desired {
		applied := current.Nodes[node]
		for _, missing := range difference(wanted, applied) {
			agent, err := r.findAgentForNode(ctx, node)
			if err != nil {
				failed.Insert(node)
				continue
			}
			if err := r.execAgentCommand(ctx, clientset, agent, missing.Add); err != nil {
				failed.Insert(node)
				continue
			}
		}
	}

	if failed.Len() > 0 {
		result.FailedNodes = failed.UnsortedList()
		result.AppliedNodes = len(desired) - failed.Len()
		return result, fmt.Errorf("agent sync failed on node(s): %s", strings.Join(result.FailedNodes, ","))
	}

	result.AppliedNodes = len(desired)
	return result, r.saveAgentState(ctx, namespace, name, agentState{Nodes: desired})
}

func (r *AegisPolicyAgentReconciler) cleanupAppliedAgentState(ctx context.Context, clientset *kubernetes.Clientset, namespace, name string) error {
	state, err := r.loadAgentState(ctx, namespace, name)
	if err != nil {
		return err
	}
	for node, rules := range state.Nodes {
		agent, err := r.findAgentForNode(ctx, node)
		if err != nil {
			continue
		}
		for _, rule := range rules {
			_ = r.execAgentCommand(ctx, clientset, agent, rule.Del)
		}
	}
	return r.deleteAgentState(ctx, namespace, name)
}

func (r *AegisPolicyAgentReconciler) updateAgentSyncStatus(ctx context.Context, ap *v1alpha1.AegisPolicy, phase, message string, appliedNodes int, degraded bool) error {
	now := metav1.Now()
	ap.Status.Phase = phase
	ap.Status.Message = message
	ap.Status.AppliedNodes = appliedNodes
	ap.Status.ObservedGeneration = ap.Generation
	ap.Status.LastAppliedAt = &now
	if degraded {
		markDegraded(&ap.Status, ap.Generation, ReasonAgentSyncFailed, message)
		setCondition(&ap.Status, ap.Generation, v1alpha1.ConditionReady, metav1.ConditionFalse, ReasonAgentSyncFailed, message)
	} else {
		setCondition(&ap.Status, ap.Generation, v1alpha1.ConditionReady, metav1.ConditionTrue, ReasonAgentSynced, message)
		setCondition(&ap.Status, ap.Generation, v1alpha1.ConditionDegraded, metav1.ConditionFalse, ReasonAgentSynced, "Live agent sync succeeded")
	}
	return r.Status().Update(ctx, ap)
}

func podSelectorForPolicy(ap *v1alpha1.AegisPolicy) (labels.Selector, error) {
	if ap.Spec.WorkloadSelector != nil && ap.Spec.WorkloadSelector.PodSelector != nil {
		return metav1.LabelSelectorAsSelector(ap.Spec.WorkloadSelector.PodSelector)
	}
	if ap.Spec.Selector != nil && len(ap.Spec.Selector.MatchLabels) > 0 {
		return labels.SelectorFromSet(labels.Set(ap.Spec.Selector.MatchLabels)), nil
	}
	return labels.Everything(), nil
}

func policyRules(spec v1alpha1.AegisPolicySpec) []agentRule {
	var rules []agentRule
	for _, decision := range policyDecisions(spec, "", 0) {
		if decision.Action == v1alpha1.RuleActionBlock {
			rules = append(rules, decision.Rule)
		}
	}
	return dedupeRules(rules)
}

func policyDecisions(spec v1alpha1.AegisPolicySpec, source string, priority int) []policyDecision {
	var decisions []policyDecision
	if spec.FileRules != nil {
		for _, rule := range spec.FileRules.Deny {
			if rule.Path == "" {
				continue
			}
			action := normalizedAction(rule.Action)
			key := "file:path:" + rule.Path
			decision := policyDecision{Key: key, Action: action, Priority: priority, Source: source}
			if action == v1alpha1.RuleActionBlock {
				decision.Rule = agentRule{
					Key: key,
					Add: []string{AgentBinaryPath, "block", "add", rule.Path},
					Del: []string{AgentBinaryPath, "block", "del", rule.Path},
				}
			}
			decisions = append(decisions, decision)
		}
	}
	if spec.NetworkRules != nil {
		for _, rule := range spec.NetworkRules.Deny {
			action := normalizedAction(rule.Action)
			if rule.IP != "" {
				key := "net:ip:" + rule.IP
				decision := policyDecision{Key: key, Action: action, Priority: priority, Source: source}
				if action == v1alpha1.RuleActionBlock {
					decision.Rule = agentRule{
						Key: key,
						Add: []string{AgentBinaryPath, "network", "deny", "add", "--ip", rule.IP},
						Del: []string{AgentBinaryPath, "network", "deny", "del", "--ip", rule.IP},
					}
				}
				decisions = append(decisions, decision)
			}
			if rule.CIDR != "" {
				key := "net:cidr:" + rule.CIDR
				decision := policyDecision{Key: key, Action: action, Priority: priority, Source: source}
				if action == v1alpha1.RuleActionBlock {
					decision.Rule = agentRule{
						Key: key,
						Add: []string{AgentBinaryPath, "network", "deny", "add", "--cidr", rule.CIDR},
						Del: []string{AgentBinaryPath, "network", "deny", "del", "--cidr", rule.CIDR},
					}
				}
				decisions = append(decisions, decision)
			}
			if rule.Port > 0 {
				key := fmt.Sprintf("net:port:%d:%s:%s", rule.Port, rule.Protocol, rule.Direction)
				decision := policyDecision{Key: key, Action: action, Priority: priority, Source: source}
				if action == v1alpha1.RuleActionBlock {
					add := []string{AgentBinaryPath, "network", "deny", "add", "--port", fmt.Sprintf("%d", rule.Port)}
					del := []string{AgentBinaryPath, "network", "deny", "del", "--port", fmt.Sprintf("%d", rule.Port)}
					if rule.Protocol != "" {
						add = append(add, "--protocol", rule.Protocol)
						del = append(del, "--protocol", rule.Protocol)
					}
					if rule.Direction != "" {
						direction := "egress"
						if rule.Direction == "inbound" {
							direction = "bind"
						}
						add = append(add, "--direction", direction)
						del = append(del, "--direction", direction)
					}
					decision.Rule = agentRule{Key: key, Add: add, Del: del}
				}
				decisions = append(decisions, decision)
			}
		}
	}
	return decisions
}

func normalizedAction(action v1alpha1.RuleAction) v1alpha1.RuleAction {
	if action == v1alpha1.RuleActionAllow {
		return v1alpha1.RuleActionAllow
	}
	return v1alpha1.RuleActionBlock
}

func difference(left, right []agentRule) []agentRule {
	rightKeys := map[string]struct{}{}
	for _, r := range right {
		rightKeys[r.Key] = struct{}{}
	}
	var out []agentRule
	for _, r := range left {
		if _, ok := rightKeys[r.Key]; !ok {
			out = append(out, r)
		}
	}
	return out
}

func dedupeRules(in []agentRule) []agentRule {
	seen := map[string]struct{}{}
	var out []agentRule
	for _, r := range in {
		if _, ok := seen[r.Key]; ok {
			continue
		}
		seen[r.Key] = struct{}{}
		out = append(out, r)
	}
	return out
}

func (r *AegisPolicyAgentReconciler) loadAgentState(ctx context.Context, namespace, name string) (agentState, error) {
	var cm corev1.ConfigMap
	err := r.Get(ctx, types.NamespacedName{Name: agentStateName(namespace, name), Namespace: SystemNamespace}, &cm)
	if apierrors.IsNotFound(err) {
		return agentState{Nodes: map[string][]agentRule{}}, nil
	}
	if err != nil {
		return agentState{}, err
	}
	var state agentState
	if err := json.Unmarshal([]byte(cm.Data["state.json"]), &state); err != nil {
		return agentState{}, err
	}
	if state.Nodes == nil {
		state.Nodes = map[string][]agentRule{}
	}
	return state, nil
}

func (r *AegisPolicyAgentReconciler) saveAgentState(ctx context.Context, namespace, name string, state agentState) error {
	if err := r.ensureStateNamespace(ctx); err != nil {
		return err
	}
	payload, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	cmName := agentStateName(namespace, name)
	var existing corev1.ConfigMap
	err = r.Get(ctx, types.NamespacedName{Name: cmName, Namespace: SystemNamespace}, &existing)
	if apierrors.IsNotFound(err) {
		return r.Create(ctx, &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      cmName,
				Namespace: SystemNamespace,
				Labels: map[string]string{
					"app.kubernetes.io/managed-by": "aegis-operator",
					"aegisbpf.io/state-kind":       "agent-sync",
				},
			},
			Data: map[string]string{"state.json": string(payload)},
		})
	}
	if err != nil {
		return err
	}
	existing.Data = map[string]string{"state.json": string(payload)}
	return r.Update(ctx, &existing)
}

func (r *AegisPolicyAgentReconciler) deleteAgentState(ctx context.Context, namespace, name string) error {
	var cm corev1.ConfigMap
	err := r.Get(ctx, types.NamespacedName{Name: agentStateName(namespace, name), Namespace: SystemNamespace}, &cm)
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	return r.Delete(ctx, &cm)
}

func (r *AegisPolicyAgentReconciler) ensureStateNamespace(ctx context.Context) error {
	var ns corev1.Namespace
	err := r.Get(ctx, types.NamespacedName{Name: SystemNamespace}, &ns)
	if apierrors.IsNotFound(err) {
		return r.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: SystemNamespace}})
	}
	return err
}

func agentStateName(namespace, name string) string {
	return AgentStatePrefix + namespace + "-" + name
}

func (r *AegisPolicyAgentReconciler) findAgentForNode(ctx context.Context, node string) (*corev1.Pod, error) {
	var agents corev1.PodList
	if err := r.List(ctx, &agents, client.InNamespace(DefaultAgentNamespace)); err != nil {
		return nil, err
	}
	for i := range agents.Items {
		agent := &agents.Items[i]
		if agent.Spec.NodeName == node && agent.Status.Phase == corev1.PodRunning && strings.Contains(agent.Name, "aegisbpf") {
			return agent, nil
		}
	}
	return nil, fmt.Errorf("no running AegisBPF agent pod on node %s", node)
}

func (r *AegisPolicyAgentReconciler) execAgentCommand(ctx context.Context, clientset *kubernetes.Clientset, pod *corev1.Pod, command []string) error {
	req := clientset.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(pod.Name).
		Namespace(pod.Namespace).
		SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: AgentContainerName,
			Command:   command,
			Stdout:    true,
			Stderr:    true,
		}, scheme.ParameterCodec)

	executor, err := remotecommand.NewSPDYExecutor(r.RestConfig, "POST", req.URL())
	if err != nil {
		return err
	}

	var stdout, stderr bytes.Buffer
	if err := executor.StreamWithContext(ctx, remotecommand.StreamOptions{Stdout: &stdout, Stderr: &stderr}); err != nil {
		return fmt.Errorf("%w: %s", err, stderr.String())
	}
	return nil
}
