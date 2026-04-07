// Package controllers implements the reconciliation logic for AegisPolicy CRDs.
package controllers

import (
	"context"
	"fmt"
	"sort"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"

	v1alpha1 "github.com/ErenAri/aegis-operator/api/v1alpha1"
	"github.com/ErenAri/aegis-operator/internal/policy"
)

const (
	// MergedConfigMapName is the ConfigMap that the DaemonSet daemon consumes.
	MergedConfigMapName = "aegis-merged-policy"

	// MergedPolicyModeKey tracks the most restrictive mode across all policies.
	MergedPolicyModeKey = "policy.mode"
)

// MergedPolicyReconciler watches all AegisPolicy and AegisClusterPolicy objects
// and produces a single merged ConfigMap in the system namespace. The DaemonSet
// daemon mounts this ConfigMap to get the combined enforcement policy.
type MergedPolicyReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=aegisbpf.io,resources=aegispolicies,verbs=get;list;watch
// +kubebuilder:rbac:groups=aegisbpf.io,resources=aegisclusterpolicies,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups="",resources=namespaces,verbs=get;list;watch

// Reconcile merges all applicable policies into a single ConfigMap.
func (r *MergedPolicyReconciler) Reconcile(ctx context.Context, _ ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// Collect all cluster-wide policies (always applicable).
	var clusterPolicies v1alpha1.AegisClusterPolicyList
	if err := r.List(ctx, &clusterPolicies); err != nil {
		return ctrl.Result{}, fmt.Errorf("listing cluster policies: %w", err)
	}

	// Collect all namespaced policies.
	var namespacedPolicies v1alpha1.AegisPolicyList
	if err := r.List(ctx, &namespacedPolicies); err != nil {
		return ctrl.Result{}, fmt.Errorf("listing namespaced policies: %w", err)
	}

	// Filter by selector and translate.
	var results []policy.TranslateResult
	hasEnforce := false

	// Sort for deterministic output.
	sort.Slice(clusterPolicies.Items, func(i, j int) bool {
		return clusterPolicies.Items[i].Name < clusterPolicies.Items[j].Name
	})
	for _, cp := range clusterPolicies.Items {
		if cp.DeletionTimestamp != nil {
			continue
		}
		if !r.selectorApplies(ctx, cp.Spec.Selector) {
			continue
		}
		result, err := policy.TranslateToINI(cp.Spec)
		if err != nil {
			logger.Error(err, "Failed to translate cluster policy", "name", cp.Name)
			continue
		}
		results = append(results, result)
		if cp.Spec.Mode == "enforce" {
			hasEnforce = true
		}
	}

	sort.Slice(namespacedPolicies.Items, func(i, j int) bool {
		a := namespacedPolicies.Items[i]
		b := namespacedPolicies.Items[j]
		if a.Namespace != b.Namespace {
			return a.Namespace < b.Namespace
		}
		return a.Name < b.Name
	})
	for _, np := range namespacedPolicies.Items {
		if np.DeletionTimestamp != nil {
			continue
		}
		if !r.selectorApplies(ctx, np.Spec.Selector) {
			continue
		}
		result, err := policy.TranslateToINI(np.Spec)
		if err != nil {
			logger.Error(err, "Failed to translate policy",
				"namespace", np.Namespace, "name", np.Name)
			continue
		}
		results = append(results, result)
		if np.Spec.Mode == "enforce" {
			hasEnforce = true
		}
	}

	if len(results) == 0 {
		// No policies — delete the merged ConfigMap if it exists.
		return r.deleteMergedConfigMap(ctx)
	}

	merged := policy.MergePolicies(results)
	mode := "audit"
	if hasEnforce {
		mode = "enforce"
	}

	logger.Info("Merged policies",
		"clusterPolicies", len(clusterPolicies.Items),
		"namespacedPolicies", len(namespacedPolicies.Items),
		"mergedHash", merged.SHA256[:12],
		"mode", mode,
	)

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      MergedConfigMapName,
			Namespace: SystemNamespace,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "aegis-operator",
				"aegisbpf.io/policy-type":      "merged",
			},
			Annotations: map[string]string{
				"aegisbpf.io/policy-hash":  merged.SHA256,
				"aegisbpf.io/last-applied": time.Now().UTC().Format(time.RFC3339),
				"aegisbpf.io/policy-count": fmt.Sprintf("%d", len(results)),
			},
		},
		Data: map[string]string{
			PolicyDataKey:       merged.INI,
			PolicyHashKey:       merged.SHA256,
			MergedPolicyModeKey: mode,
		},
	}

	var existing corev1.ConfigMap
	err := r.Get(ctx, types.NamespacedName{Name: MergedConfigMapName, Namespace: SystemNamespace}, &existing)
	if errors.IsNotFound(err) {
		if nsErr := r.ensureNamespace(ctx); nsErr != nil {
			return ctrl.Result{}, nsErr
		}
		logger.Info("Creating merged policy ConfigMap")
		if err := r.Create(ctx, cm); err != nil {
			return ctrl.Result{RequeueAfter: 10 * time.Second}, err
		}
	} else if err != nil {
		return ctrl.Result{}, err
	} else if existing.Data[PolicyHashKey] != merged.SHA256 {
		existing.Data = cm.Data
		existing.Labels = cm.Labels
		existing.Annotations = cm.Annotations
		logger.Info("Updating merged policy ConfigMap", "newHash", merged.SHA256[:12])
		if err := r.Update(ctx, &existing); err != nil {
			return ctrl.Result{RequeueAfter: 10 * time.Second}, err
		}
	}

	return ctrl.Result{}, nil
}

// SetupWithManager configures the controller to watch both policy types.
func (r *MergedPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("merged-policy").
		Watches(&v1alpha1.AegisPolicy{}, &handler.EnqueueRequestForObject{}).
		Watches(&v1alpha1.AegisClusterPolicy{}, &handler.EnqueueRequestForObject{}).
		Complete(r)
}

// selectorApplies checks whether the policy's selector is satisfied.
// A nil or empty selector applies to all workloads.
func (r *MergedPolicyReconciler) selectorApplies(ctx context.Context, selector *v1alpha1.PolicySelector) bool {
	if selector == nil {
		return true
	}

	// Namespace filtering: if matchNamespaces is set, verify at least one exists.
	if len(selector.MatchNamespaces) > 0 {
		for _, ns := range selector.MatchNamespaces {
			var namespace corev1.Namespace
			if err := r.Get(ctx, types.NamespacedName{Name: ns}, &namespace); err == nil {
				return true
			}
		}
		return false
	}

	// Label filtering: if matchLabels is set, check for pods with matching labels.
	if len(selector.MatchLabels) > 0 {
		var pods corev1.PodList
		if err := r.List(ctx, &pods, client.MatchingLabels(selector.MatchLabels)); err == nil {
			return len(pods.Items) > 0
		}
		return false
	}

	return true
}

func (r *MergedPolicyReconciler) deleteMergedConfigMap(ctx context.Context) (ctrl.Result, error) {
	var cm corev1.ConfigMap
	err := r.Get(ctx, types.NamespacedName{Name: MergedConfigMapName, Namespace: SystemNamespace}, &cm)
	if errors.IsNotFound(err) {
		return ctrl.Result{}, nil
	}
	if err != nil {
		return ctrl.Result{}, err
	}
	log.FromContext(ctx).Info("Deleting merged policy ConfigMap (no policies remain)")
	return ctrl.Result{}, r.Delete(ctx, &cm)
}

func (r *MergedPolicyReconciler) ensureNamespace(ctx context.Context) error {
	var ns corev1.Namespace
	err := r.Get(ctx, types.NamespacedName{Name: SystemNamespace}, &ns)
	if errors.IsNotFound(err) {
		ns = corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name:   SystemNamespace,
				Labels: map[string]string{"app.kubernetes.io/managed-by": "aegis-operator"},
			},
		}
		return r.Create(ctx, &ns)
	}
	return err
}
