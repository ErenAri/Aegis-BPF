package controllers

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	v1alpha1 "github.com/ErenAri/aegis-operator/api/v1alpha1"
)

const (
	DefaultAgentNamespace = "aegisbpf"
	AgentContainerName    = "aegisbpf"
	AgentBinaryPath       = "/usr/bin/aegisbpf"
	AgentSyncInterval     = 30 * time.Second
)

// AegisPolicyAgentReconciler continuously applies namespaced AegisPolicy
// resources to the AegisBPF DaemonSet pods that run on matching workload nodes.
//
// This is intentionally a thin Kubernetes-native bridge: it reuses the existing
// daemon CLI instead of changing the BPF data plane or policy engine.
type AegisPolicyAgentReconciler struct {
	client.Client
	Scheme     *runtime.Scheme
	RestConfig *rest.Config
}

// +kubebuilder:rbac:groups=aegisbpf.io,resources=aegispolicies,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=pods/exec,verbs=create

func (r *AegisPolicyAgentReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx).WithName("agent-sync")

	var ap v1alpha1.AegisPolicy
	if err := r.Get(ctx, req.NamespacedName, &ap); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !ap.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}

	podSelector, err := podSelectorForPolicy(&ap)
	if err != nil {
		logger.Error(err, "invalid workload selector")
		return ctrl.Result{RequeueAfter: AgentSyncInterval}, nil
	}

	var pods corev1.PodList
	if err := r.List(ctx, &pods, client.InNamespace(ap.Namespace), client.MatchingLabelsSelector{Selector: podSelector}); err != nil {
		return ctrl.Result{}, err
	}

	nodes := sets.New[string]()
	for _, pod := range pods.Items {
		if pod.Spec.NodeName != "" && pod.Status.Phase == corev1.PodRunning {
			nodes.Insert(pod.Spec.NodeName)
		}
	}
	if nodes.Len() == 0 {
		logger.Info("no running matching workloads", "policy", ap.Name)
		return ctrl.Result{RequeueAfter: AgentSyncInterval}, nil
	}

	commands := policyCommands(ap.Spec)
	if len(commands) == 0 {
		logger.Info("policy has no live-agent rules", "policy", ap.Name)
		return ctrl.Result{RequeueAfter: AgentSyncInterval}, nil
	}

	clientset, err := kubernetes.NewForConfig(r.RestConfig)
	if err != nil {
		return ctrl.Result{}, err
	}

	for _, node := range nodes.UnsortedList() {
		agent, err := r.findAgentForNode(ctx, node)
		if err != nil {
			logger.Error(err, "agent pod not found for node", "node", node)
			continue
		}
		for _, cmd := range commands {
			if err := r.execAgentCommand(ctx, clientset, agent, cmd); err != nil {
				logger.Error(err, "agent command failed", "node", node, "agent", agent.Name, "command", strings.Join(cmd, " "))
				continue
			}
		}
		logger.Info("policy synced to agent", "policy", ap.Name, "node", node, "agent", agent.Name, "commands", len(commands))
	}

	return ctrl.Result{RequeueAfter: AgentSyncInterval}, nil
}

func (r *AegisPolicyAgentReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("aegispolicy-agent-sync").
		For(&v1alpha1.AegisPolicy{}).
		Complete(r)
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

func policyCommands(spec v1alpha1.AegisPolicySpec) [][]string {
	var commands [][]string
	if spec.FileRules != nil {
		for _, rule := range spec.FileRules.Deny {
			if rule.Action == v1alpha1.RuleActionAllow {
				continue
			}
			if rule.Path != "" {
				commands = append(commands, []string{AgentBinaryPath, "block", "add", rule.Path})
			}
		}
	}
	if spec.NetworkRules != nil {
		for _, rule := range spec.NetworkRules.Deny {
			if rule.Action == v1alpha1.RuleActionAllow {
				continue
			}
			if rule.IP != "" {
				commands = append(commands, []string{AgentBinaryPath, "network", "deny", "add", "--ip", rule.IP})
			}
			if rule.CIDR != "" {
				commands = append(commands, []string{AgentBinaryPath, "network", "deny", "add", "--cidr", rule.CIDR})
			}
			if rule.Port > 0 {
				cmd := []string{AgentBinaryPath, "network", "deny", "add", "--port", fmt.Sprintf("%d", rule.Port)}
				if rule.Protocol != "" {
					cmd = append(cmd, "--protocol", rule.Protocol)
				}
				if rule.Direction != "" {
					direction := "egress"
					if rule.Direction == "inbound" {
						direction = "bind"
					}
					cmd = append(cmd, "--direction", direction)
				}
				commands = append(commands, cmd)
			}
		}
	}
	return commands
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
