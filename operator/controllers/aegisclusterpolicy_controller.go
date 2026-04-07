package controllers

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	v1alpha1 "github.com/ErenAri/aegis-operator/api/v1alpha1"
	"github.com/ErenAri/aegis-operator/internal/policy"
)

const (
	// ClusterConfigMapPrefix is the prefix for cluster-scoped policy ConfigMaps.
	ClusterConfigMapPrefix = "aegis-cluster-policy-"

	// ClusterFinalizerName is the finalizer for AegisClusterPolicy resources.
	ClusterFinalizerName = "aegisbpf.io/cluster-policy-finalizer"
)

// AegisClusterPolicyReconciler reconciles AegisClusterPolicy objects.
type AegisClusterPolicyReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=aegisbpf.io,resources=aegisclusterpolicies,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=aegisbpf.io,resources=aegisclusterpolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=aegisbpf.io,resources=aegisclusterpolicies/finalizers,verbs=update

// Reconcile translates an AegisClusterPolicy CRD into a ConfigMap.
func (r *AegisClusterPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var acp v1alpha1.AegisClusterPolicy
	if err := r.Get(ctx, req.NamespacedName, &acp); err != nil {
		if errors.IsNotFound(err) {
			return r.cleanupConfigMap(ctx, req.Name)
		}
		return ctrl.Result{}, err
	}

	// Handle deletion.
	if !acp.DeletionTimestamp.IsZero() {
		if controllerutil.ContainsFinalizer(&acp, ClusterFinalizerName) {
			if _, err := r.cleanupConfigMap(ctx, req.Name); err != nil {
				return ctrl.Result{}, err
			}
			controllerutil.RemoveFinalizer(&acp, ClusterFinalizerName)
			if err := r.Update(ctx, &acp); err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
	}

	// Ensure finalizer.
	if !controllerutil.ContainsFinalizer(&acp, ClusterFinalizerName) {
		controllerutil.AddFinalizer(&acp, ClusterFinalizerName)
		if err := r.Update(ctx, &acp); err != nil {
			return ctrl.Result{}, err
		}
	}

	// Translate CRD → INI.
	result, err := policy.TranslateToINI(acp.Spec)
	if err != nil {
		logger.Error(err, "Failed to translate cluster policy")
		markPolicyInvalid(&acp.Status, acp.Generation,
			v1alpha1.ReasonTranslationFailed,
			fmt.Sprintf("Translation failed: %v", err))
		return r.updateStatus(ctx, &acp, "Error", fmt.Sprintf("Translation failed: %v", err), "")
	}
	markPolicyValid(&acp.Status, acp.Generation)
	markEnforceCapableUnknown(&acp.Status, acp.Generation)

	logger.Info("Translated cluster policy",
		"name", acp.Name,
		"hash", result.SHA256[:12],
		"mode", acp.Spec.Mode,
	)

	// Create/update ConfigMap.
	cmName := ClusterConfigMapPrefix + acp.Name
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cmName,
			Namespace: SystemNamespace,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "aegis-operator",
				"aegisbpf.io/policy-source":    acp.Name,
				"aegisbpf.io/policy-scope":     "cluster",
			},
			Annotations: map[string]string{
				"aegisbpf.io/policy-hash":  result.SHA256,
				"aegisbpf.io/last-applied": time.Now().UTC().Format(time.RFC3339),
			},
		},
		Data: map[string]string{
			PolicyDataKey: result.INI,
			PolicyHashKey: result.SHA256,
			PolicyModeKey: acp.Spec.Mode,
		},
	}

	var existing corev1.ConfigMap
	err = r.Get(ctx, types.NamespacedName{Name: cmName, Namespace: SystemNamespace}, &existing)
	if errors.IsNotFound(err) {
		if nsErr := r.ensureNamespace(ctx); nsErr != nil {
			return ctrl.Result{}, nsErr
		}
		if err := r.Create(ctx, cm); err != nil {
			markDegraded(&acp.Status, acp.Generation,
				v1alpha1.ReasonConfigMapWriteFailed,
				fmt.Sprintf("ConfigMap create failed: %v", err))
			return r.updateStatus(ctx, &acp, "Error", fmt.Sprintf("ConfigMap create failed: %v", err), "")
		}
	} else if err != nil {
		return ctrl.Result{}, err
	} else {
		if existing.Data[PolicyHashKey] != result.SHA256 {
			existing.Data = cm.Data
			existing.Labels = cm.Labels
			existing.Annotations = cm.Annotations
			if err := r.Update(ctx, &existing); err != nil {
				markDegraded(&acp.Status, acp.Generation,
					v1alpha1.ReasonConfigMapWriteFailed,
					fmt.Sprintf("ConfigMap update failed: %v", err))
				return r.updateStatus(ctx, &acp, "Error", fmt.Sprintf("ConfigMap update failed: %v", err), "")
			}
		}
	}

	markReady(&acp.Status, acp.Generation, "Cluster policy translated and ConfigMap written")
	return r.updateStatus(ctx, &acp, "Applied", "Cluster policy applied successfully", result.SHA256)
}

// SetupWithManager sets up the controller with the Manager.
func (r *AegisClusterPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.AegisClusterPolicy{}).
		Complete(r)
}

func (r *AegisClusterPolicyReconciler) updateStatus(
	ctx context.Context,
	acp *v1alpha1.AegisClusterPolicy,
	phase, message, hash string,
) (ctrl.Result, error) {
	now := metav1.Now()
	acp.Status.Phase = phase
	acp.Status.Message = message
	acp.Status.PolicyHash = hash
	acp.Status.ObservedGeneration = acp.Generation
	if phase == "Applied" {
		acp.Status.LastAppliedAt = &now
	}
	if err := r.Status().Update(ctx, acp); err != nil {
		log.FromContext(ctx).Error(err, "Failed to update AegisClusterPolicy status")
		return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
	}
	if phase == "Error" {
		return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
	}
	return ctrl.Result{}, nil
}

func (r *AegisClusterPolicyReconciler) cleanupConfigMap(ctx context.Context, name string) (ctrl.Result, error) {
	cmName := ClusterConfigMapPrefix + name
	var cm corev1.ConfigMap
	err := r.Get(ctx, types.NamespacedName{Name: cmName, Namespace: SystemNamespace}, &cm)
	if errors.IsNotFound(err) {
		return ctrl.Result{}, nil
	}
	if err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, r.Delete(ctx, &cm)
}

func (r *AegisClusterPolicyReconciler) ensureNamespace(ctx context.Context) error {
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
