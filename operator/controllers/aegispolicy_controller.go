// Package controllers implements the reconciliation logic for AegisPolicy CRDs.
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
	// SystemNamespace is where generated policy ConfigMaps are created.
	SystemNamespace = "aegisbpf-system"

	// ConfigMapPrefix is the prefix for generated policy ConfigMaps.
	ConfigMapPrefix = "aegis-policy-"

	// FinalizerName is the finalizer added to AegisPolicy resources.
	FinalizerName = "aegisbpf.io/policy-finalizer"

	// PolicyDataKey is the key in the ConfigMap data holding the INI policy.
	PolicyDataKey = "policy.conf"

	// PolicyHashKey is the key in the ConfigMap data holding the SHA-256 hash.
	PolicyHashKey = "policy.sha256"

	// PolicyModeKey is the key in the ConfigMap data holding the enforcement mode.
	PolicyModeKey = "policy.mode"
)

// AegisPolicyReconciler reconciles AegisPolicy objects.
type AegisPolicyReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=aegisbpf.io,resources=aegispolicies,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=aegisbpf.io,resources=aegispolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=aegisbpf.io,resources=aegispolicies/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// Reconcile translates an AegisPolicy CRD into a ConfigMap for the DaemonSet.
func (r *AegisPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// Fetch the AegisPolicy instance.
	var ap v1alpha1.AegisPolicy
	if err := r.Get(ctx, req.NamespacedName, &ap); err != nil {
		if errors.IsNotFound(err) {
			logger.Info("AegisPolicy deleted, cleaning up ConfigMap")
			return r.cleanupConfigMap(ctx, req.NamespacedName)
		}
		return ctrl.Result{}, err
	}

	// Handle deletion via finalizer.
	if !ap.DeletionTimestamp.IsZero() {
		if controllerutil.ContainsFinalizer(&ap, FinalizerName) {
			if _, err := r.cleanupConfigMap(ctx, req.NamespacedName); err != nil {
				return ctrl.Result{}, err
			}
			controllerutil.RemoveFinalizer(&ap, FinalizerName)
			if err := r.Update(ctx, &ap); err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
	}

	// Ensure finalizer is set.
	if !controllerutil.ContainsFinalizer(&ap, FinalizerName) {
		controllerutil.AddFinalizer(&ap, FinalizerName)
		if err := r.Update(ctx, &ap); err != nil {
			return ctrl.Result{}, err
		}
	}

	// Translate CRD spec → INI policy.
	result, err := policy.TranslateToINI(ap.Spec)
	if err != nil {
		logger.Error(err, "Failed to translate policy")
		markPolicyInvalid(&ap.Status, ap.Generation,
			v1alpha1.ReasonTranslationFailed,
			fmt.Sprintf("Translation failed: %v", err))
		return r.updateStatus(ctx, &ap, "Error", fmt.Sprintf("Translation failed: %v", err), "")
	}
	markPolicyValid(&ap.Status, ap.Generation)
	markEnforceCapableUnknown(&ap.Status, ap.Generation)

	logger.Info("Translated policy",
		"namespace", ap.Namespace,
		"name", ap.Name,
		"hash", result.SHA256[:12],
		"mode", ap.Spec.Mode,
	)

	// Create or update the ConfigMap.
	cmName := configMapName(ap.Namespace, ap.Name)
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cmName,
			Namespace: SystemNamespace,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "aegis-operator",
				"aegisbpf.io/policy-source":    ap.Name,
				"aegisbpf.io/source-namespace": ap.Namespace,
			},
			Annotations: map[string]string{
				"aegisbpf.io/policy-hash":   result.SHA256,
				"aegisbpf.io/last-applied":  time.Now().UTC().Format(time.RFC3339),
				"aegisbpf.io/source-policy": fmt.Sprintf("%s/%s", ap.Namespace, ap.Name),
			},
		},
		Data: map[string]string{
			PolicyDataKey: result.INI,
			PolicyHashKey: result.SHA256,
			PolicyModeKey: ap.Spec.Mode,
		},
	}

	// Create or update.
	var existing corev1.ConfigMap
	err = r.Get(ctx, types.NamespacedName{Name: cmName, Namespace: SystemNamespace}, &existing)
	if errors.IsNotFound(err) {
		// Ensure namespace exists.
		if nsErr := r.ensureNamespace(ctx); nsErr != nil {
			return ctrl.Result{}, nsErr
		}
		logger.Info("Creating policy ConfigMap", "configmap", cmName)
		if err := r.Create(ctx, cm); err != nil {
			markDegraded(&ap.Status, ap.Generation,
				v1alpha1.ReasonConfigMapWriteFailed,
				fmt.Sprintf("ConfigMap create failed: %v", err))
			return r.updateStatus(ctx, &ap, "Error", fmt.Sprintf("ConfigMap create failed: %v", err), "")
		}
	} else if err != nil {
		return ctrl.Result{}, err
	} else {
		// Update existing ConfigMap if hash changed.
		if existing.Data[PolicyHashKey] == result.SHA256 {
			logger.V(1).Info("Policy unchanged, skipping update", "hash", result.SHA256[:12])
		} else {
			existing.Data = cm.Data
			existing.Labels = cm.Labels
			existing.Annotations = cm.Annotations
			logger.Info("Updating policy ConfigMap", "configmap", cmName, "newHash", result.SHA256[:12])
			if err := r.Update(ctx, &existing); err != nil {
				markDegraded(&ap.Status, ap.Generation,
					v1alpha1.ReasonConfigMapWriteFailed,
					fmt.Sprintf("ConfigMap update failed: %v", err))
				return r.updateStatus(ctx, &ap, "Error", fmt.Sprintf("ConfigMap update failed: %v", err), "")
			}
		}
	}

	markReady(&ap.Status, ap.Generation, "Policy translated and ConfigMap written")
	return r.updateStatus(ctx, &ap, "Applied", "Policy applied successfully", result.SHA256)
}

// SetupWithManager sets up the controller with the Manager.
func (r *AegisPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.AegisPolicy{}).
		Owns(&corev1.ConfigMap{}).
		Complete(r)
}

func (r *AegisPolicyReconciler) updateStatus(
	ctx context.Context,
	ap *v1alpha1.AegisPolicy,
	phase, message, hash string,
) (ctrl.Result, error) {
	now := metav1.Now()
	ap.Status.Phase = phase
	ap.Status.Message = message
	ap.Status.PolicyHash = hash
	ap.Status.ObservedGeneration = ap.Generation
	if phase == "Applied" {
		ap.Status.LastAppliedAt = &now
	}
	if err := r.Status().Update(ctx, ap); err != nil {
		log.FromContext(ctx).Error(err, "Failed to update AegisPolicy status")
		return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
	}
	if phase == "Error" {
		return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
	}
	return ctrl.Result{}, nil
}

func (r *AegisPolicyReconciler) cleanupConfigMap(ctx context.Context, nn types.NamespacedName) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	cmName := configMapName(nn.Namespace, nn.Name)
	var cm corev1.ConfigMap
	err := r.Get(ctx, types.NamespacedName{Name: cmName, Namespace: SystemNamespace}, &cm)
	if errors.IsNotFound(err) {
		return ctrl.Result{}, nil
	}
	if err != nil {
		return ctrl.Result{}, err
	}
	logger.Info("Deleting policy ConfigMap", "configmap", cmName)
	return ctrl.Result{}, r.Delete(ctx, &cm)
}

func (r *AegisPolicyReconciler) ensureNamespace(ctx context.Context) error {
	var ns corev1.Namespace
	err := r.Get(ctx, types.NamespacedName{Name: SystemNamespace}, &ns)
	if errors.IsNotFound(err) {
		ns = corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: SystemNamespace,
				Labels: map[string]string{
					"app.kubernetes.io/managed-by": "aegis-operator",
				},
			},
		}
		return r.Create(ctx, &ns)
	}
	return err
}

func configMapName(namespace, name string) string {
	return ConfigMapPrefix + namespace + "-" + name
}
