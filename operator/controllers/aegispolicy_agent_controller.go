package controllers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
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
	DefaultAgentNamespace = "aegisbpf"
	AgentContainerName    = "aegisbpf"
	AgentBinaryPath       = "/usr/bin/aegisbpf"
	AgentSyncInterval     = 30 * time.Second
	AgentSyncFinalizer    = "aegisbpf.io/agent-sync-finalizer"
	AgentStatePrefix      = "aegis-agent-state-"
	ReasonAgentSyncFailed = "AgentSyncFailed"
	ReasonAgentSynced     = "AgentSynced"
)

type agentRule struct {
	Key string   `json:"key"`
	Add []string `json:"add"`
	Del []string `json:"del"`
}

type agentState struct {
	Nodes map[string][]agentRule `json:"nodes"`
}

type agentSyncResult struct {
	AppliedNodes int
	FailedNodes  []string
}

// AegisPolicyAgentReconciler continuously applies namespaced AegisPolicy
// resources to the AegisBPF DaemonSet pods that run on matching workload nodes.
//
// It persists the last applied per-node rule set in a controller-owned
// ConfigMap, then uses desired-vs-current diffing to avoid duplicate writes and
// to remove stale rules on policy update/delete.
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
			if err := r.cleanupAppliedAgentState(ctx, clientset, ap.Namespace, ap.Name); err != nil {
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

	podSelector, err := podSelectorForPolicy(&ap)
	if err != nil {
		logger.Error(err, "invalid workload selector")
		_ = r.updateAgentSyncStatus(ctx, &ap, "Error", fmt.Sprintf("Invalid workload selector: %v", err), 0, true)
		return ctrl.Result{RequeueAfter: AgentSyncInterval}, nil
	}

	var pods corev1.PodList
	if err := r.List(ctx, &pods, client.InNamespace(ap.Namespace), client.MatchingLabelsSelector{Selector: podSelector}); err != nil {
		_ = r.updateAgentSyncStatus(ctx, &ap, "Error", fmt.Sprintf("Pod list failed: %v", err), 0, true)
		return ctrl.Result{}, err
	}

	nodes := sets.New[string]()
	for _, pod := range pods.Items {
		if pod.Spec.NodeName != "" && pod.Status.Phase == corev1.PodRunning {
			nodes.Insert(pod.Spec.NodeName)
		}
	}

	desiredRules := policyRules(ap.Spec)
	if len(desiredRules) == 0 || nodes.Len() == 0 {
		result, err := r.reconcileAgentRules(ctx, clientset, ap.Namespace, ap.Name, map[string][]agentRule{})
		if err != nil {
			_ = r.updateAgentSyncStatus(ctx, &ap, "Error", fmt.Sprintf("Agent cleanup reconcile failed: %v", err), result.AppliedNodes, true)
			return ctrl.Result{RequeueAfter: AgentSyncInterval}, err
		}
		message := "No matching running workloads or no live-agent rules; stale rules cleaned up"
		logger.Info(message, "policy", ap.Name)
		_ = r.updateAgentSyncStatus(ctx, &ap, "Applied", message, result.AppliedNodes, false)
		return ctrl.Result{RequeueAfter: AgentSyncInterval}, nil
	}

	desired := map[string][]agentRule{}
	for _, node := range nodes.UnsortedList() {
		desired[node] = desiredRules
	}

	result, err := r.reconcileAgentRules(ctx, clientset, ap.Namespace, ap.Name, desired)
	if err != nil {
		message := fmt.Sprintf("Agent sync failed after %d/%d nodes: %v", result.AppliedNodes, len(desired), err)
		_ = r.updateAgentSyncStatus(ctx, &ap, "Error", message, result.AppliedNodes, true)
		return ctrl.Result{RequeueAfter: AgentSyncInterval}, err
	}

	message := fmt.Sprintf("Agent sync applied to %d node(s), %d rule(s) each", result.AppliedNodes, len(desiredRules))
	logger.Info("policy agent state reconciled", "policy", ap.Name, "nodes", len(desired), "rules", len(desiredRules))
	_ = r.updateAgentSyncStatus(ctx, &ap, "Applied", message, result.AppliedNodes, false)
	return ctrl.Result{RequeueAfter: AgentSyncInterval}, nil
}

func (r *AegisPolicyAgentReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("aegispolicy-agent-sync").
		For(&v1alpha1.AegisPolicy{}).
		Complete(r)
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
	if spec.FileRules != nil {
		for _, rule := range spec.FileRules.Deny {
			if rule.Action == v1alpha1.RuleActionAllow || rule.Path == "" {
				continue
			}
			rules = append(rules, agentRule{
				Key: "file:path:" + rule.Path,
				Add: []string{AgentBinaryPath, "block", "add", rule.Path},
				Del: []string{AgentBinaryPath, "block", "del", rule.Path},
			})
		}
	}
	if spec.NetworkRules != nil {
		for _, rule := range spec.NetworkRules.Deny {
			if rule.Action == v1alpha1.RuleActionAllow {
				continue
			}
			if rule.IP != "" {
				rules = append(rules, agentRule{
					Key: "net:ip:" + rule.IP,
					Add: []string{AgentBinaryPath, "network", "deny", "add", "--ip", rule.IP},
					Del: []string{AgentBinaryPath, "network", "deny", "del", "--ip", rule.IP},
				})
			}
			if rule.CIDR != "" {
				rules = append(rules, agentRule{
					Key: "net:cidr:" + rule.CIDR,
					Add: []string{AgentBinaryPath, "network", "deny", "add", "--cidr", rule.CIDR},
					Del: []string{AgentBinaryPath, "network", "deny", "del", "--cidr", rule.CIDR},
				})
			}
			if rule.Port > 0 {
				key := fmt.Sprintf("net:port:%d:%s:%s", rule.Port, rule.Protocol, rule.Direction)
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
				rules = append(rules, agentRule{Key: key, Add: add, Del: del})
			}
		}
	}
	return dedupeRules(rules)
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
