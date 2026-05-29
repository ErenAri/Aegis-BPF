package controllers

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	// LabelArenaCapable is set to "true" on nodes with kernel >= 6.9 (BPF arena support).
	LabelArenaCapable = "aegisbpf.io/arena-capable"

	// LabelBPFLSMCapable is set to "true" on nodes with kernel >= 5.7 (BPF LSM support).
	// This is required for enforce mode — without BPF LSM, only audit mode works.
	LabelBPFLSMCapable = "aegisbpf.io/bpf-lsm-capable"

	// LabelKernelVersion records the parsed major.minor kernel version.
	LabelKernelVersion = "aegisbpf.io/kernel-version"
)

// NodeFeatureReconciler watches Node objects and labels them with
// BPF capability information derived from kernel version.
type NodeFeatureReconciler struct {
	client.Client
}

// +kubebuilder:rbac:groups="",resources=nodes,verbs=get;list;watch;update;patch

func (r *NodeFeatureReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx).WithName("node-feature")

	var node corev1.Node
	if err := r.Get(ctx, req.NamespacedName, &node); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Parse kernel version from node status.
	kernelVersion := node.Status.NodeInfo.KernelVersion
	major, minor, err := parseKernelVersion(kernelVersion)
	if err != nil {
		logger.V(1).Info("Cannot parse kernel version", "node", node.Name, "kernel", kernelVersion)
		return ctrl.Result{}, nil
	}

	arenaCapable := major > 6 || (major == 6 && minor >= 9)
	bpfLSMCapable := major > 5 || (major == 5 && minor >= 7)
	arenaStr := strconv.FormatBool(arenaCapable)
	bpfLSMStr := strconv.FormatBool(bpfLSMCapable)
	versionStr := fmt.Sprintf("%d.%d", major, minor)

	// Check if labels already match — avoid unnecessary updates.
	if node.Labels[LabelArenaCapable] == arenaStr &&
		node.Labels[LabelBPFLSMCapable] == bpfLSMStr &&
		node.Labels[LabelKernelVersion] == versionStr {
		return ctrl.Result{}, nil
	}

	// Patch labels.
	patch := client.MergeFrom(node.DeepCopy())
	if node.Labels == nil {
		node.Labels = map[string]string{}
	}
	node.Labels[LabelArenaCapable] = arenaStr
	node.Labels[LabelBPFLSMCapable] = bpfLSMStr
	node.Labels[LabelKernelVersion] = versionStr

	if err := r.Patch(ctx, &node, patch); err != nil {
		logger.Error(err, "Failed to patch node labels", "node", node.Name)
		return ctrl.Result{}, err
	}

	logger.Info("Node labeled",
		"node", node.Name,
		"kernel", versionStr,
		"arena-capable", arenaCapable,
	)
	return ctrl.Result{}, nil
}

func (r *NodeFeatureReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("node-feature-discovery").
		For(&corev1.Node{}).
		Complete(r)
}

// parseKernelVersion extracts major and minor from a kernel version string
// like "6.9.0-generic" or "5.15.0-1064-azure".
func parseKernelVersion(version string) (int, int, error) {
	// Strip any leading non-digit prefix (rare but possible).
	parts := strings.SplitN(version, ".", 3)
	if len(parts) < 2 {
		return 0, 0, fmt.Errorf("unexpected kernel version format: %s", version)
	}

	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, fmt.Errorf("cannot parse major: %w", err)
	}

	// Minor may have a suffix like "9-generic", strip it.
	minorStr := parts[1]
	for i, c := range minorStr {
		if c < '0' || c > '9' {
			minorStr = minorStr[:i]
			break
		}
	}

	minor, err := strconv.Atoi(minorStr)
	if err != nil {
		return 0, 0, fmt.Errorf("cannot parse minor: %w", err)
	}

	return major, minor, nil
}
