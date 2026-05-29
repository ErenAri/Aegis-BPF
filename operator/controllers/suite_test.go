package controllers

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	v1alpha1 "github.com/ErenAri/aegis-operator/api/v1alpha1"
)

// envtestAvailable checks whether the envtest binaries (etcd, kube-apiserver)
// are installed. Returns false in CI and local environments without setup-envtest.
func envtestAvailable() bool {
	// KUBEBUILDER_ASSETS overrides the default path.
	if dir := os.Getenv("KUBEBUILDER_ASSETS"); dir != "" {
		if _, err := os.Stat(filepath.Join(dir, "etcd")); err == nil {
			return true
		}
	}
	// Default location used by controller-runtime.
	if _, err := os.Stat("/usr/local/kubebuilder/bin/etcd"); err == nil {
		return true
	}
	return false
}

func TestReconciler_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	if !envtestAvailable() {
		t.Skip("skipping integration test: envtest binaries not installed (install with setup-envtest)")
	}

	// Start envtest API server with CRDs.
	testEnv := &envtest.Environment{
		CRDDirectoryPaths: []string{
			filepath.Join("..", "config", "crd"),
		},
		ErrorIfCRDPathMissing: true,
	}

	cfg, err := testEnv.Start()
	if err != nil {
		t.Fatalf("failed to start envtest: %v", err)
	}
	defer testEnv.Stop()

	// Register scheme.
	if err := v1alpha1.AddToScheme(scheme.Scheme); err != nil {
		t.Fatalf("failed to add v1alpha1 to scheme: %v", err)
	}

	// Create manager.
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme: scheme.Scheme,
	})
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	// Register reconciler.
	reconciler := &AegisPolicyReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}
	if err := reconciler.SetupWithManager(mgr); err != nil {
		t.Fatalf("failed to setup reconciler: %v", err)
	}

	// Start manager in background.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		if err := mgr.Start(ctx); err != nil {
			t.Logf("manager exited: %v", err)
		}
	}()

	// Wait for cache sync.
	if !mgr.GetCache().WaitForCacheSync(ctx) {
		t.Fatal("cache sync failed")
	}

	k8sClient := mgr.GetClient()

	// Create aegisbpf-system namespace (reconciler expects it).
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: SystemNamespace}}
	if err := k8sClient.Create(ctx, ns); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatalf("failed to create namespace: %v", err)
	}

	t.Run("create_policy_generates_configmap", func(t *testing.T) {
		ap := &v1alpha1.AegisPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-exec-deny",
				Namespace: "default",
			},
			Spec: v1alpha1.AegisPolicySpec{
				Mode: "enforce",
				ExecRules: &v1alpha1.ExecRules{
					DenyComm: []string{"xmrig"},
				},
			},
		}

		if err := k8sClient.Create(ctx, ap); err != nil {
			t.Fatalf("failed to create AegisPolicy: %v", err)
		}
		defer k8sClient.Delete(ctx, ap)

		// Wait for ConfigMap to appear.
		cmName := configMapName("default", "test-exec-deny")
		cmKey := types.NamespacedName{Name: cmName, Namespace: SystemNamespace}
		var cm corev1.ConfigMap

		if err := waitFor(ctx, k8sClient, cmKey, &cm, 10*time.Second); err != nil {
			t.Fatalf("ConfigMap %s not created: %v", cmName, err)
		}

		// Verify INI content.
		if _, ok := cm.Data[PolicyDataKey]; !ok {
			t.Error("ConfigMap missing policy.conf key")
		}

		// Verify aegis-next content.
		nextContent, ok := cm.Data[NextPolicyDataKey]
		if !ok {
			t.Error("ConfigMap missing policy.next key")
		}
		if nextContent == "" {
			t.Error("policy.next content is empty")
		}

		// Verify hash.
		if cm.Data[PolicyHashKey] == "" {
			t.Error("policy hash is empty")
		}
		if cm.Data[NextPolicyHashKey] == "" {
			t.Error("aegis-next policy hash is empty")
		}

		// Verify mode.
		if cm.Data[PolicyModeKey] != "enforce" {
			t.Errorf("expected mode=enforce, got %s", cm.Data[PolicyModeKey])
		}
	})

	t.Run("update_policy_updates_configmap", func(t *testing.T) {
		ap := &v1alpha1.AegisPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-update",
				Namespace: "default",
			},
			Spec: v1alpha1.AegisPolicySpec{
				Mode: "enforce",
				ExecRules: &v1alpha1.ExecRules{
					DenyComm: []string{"ncat"},
				},
			},
		}

		if err := k8sClient.Create(ctx, ap); err != nil {
			t.Fatalf("failed to create AegisPolicy: %v", err)
		}
		defer k8sClient.Delete(ctx, ap)

		cmName := configMapName("default", "test-update")
		cmKey := types.NamespacedName{Name: cmName, Namespace: SystemNamespace}
		var cm corev1.ConfigMap

		if err := waitFor(ctx, k8sClient, cmKey, &cm, 10*time.Second); err != nil {
			t.Fatalf("ConfigMap not created: %v", err)
		}
		originalHash := cm.Data[PolicyHashKey]

		// Update policy — add another comm.
		if err := k8sClient.Get(ctx, types.NamespacedName{Name: "test-update", Namespace: "default"}, ap); err != nil {
			t.Fatalf("failed to get AegisPolicy: %v", err)
		}
		ap.Spec.ExecRules.DenyComm = append(ap.Spec.ExecRules.DenyComm, "socat")
		if err := k8sClient.Update(ctx, ap); err != nil {
			t.Fatalf("failed to update AegisPolicy: %v", err)
		}

		// Wait for hash to change.
		if err := waitForCondition(ctx, k8sClient, cmKey, &cm, 10*time.Second, func() bool {
			return cm.Data[PolicyHashKey] != originalHash
		}); err != nil {
			t.Fatal("ConfigMap hash did not change after policy update")
		}
	})

	t.Run("delete_policy_removes_configmap", func(t *testing.T) {
		ap := &v1alpha1.AegisPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-delete",
				Namespace: "default",
			},
			Spec: v1alpha1.AegisPolicySpec{
				Mode: "audit",
				FileRules: &v1alpha1.FileRules{
					Deny: []v1alpha1.FileRule{{Path: "/etc/shadow"}},
				},
			},
		}

		if err := k8sClient.Create(ctx, ap); err != nil {
			t.Fatalf("failed to create AegisPolicy: %v", err)
		}

		cmName := configMapName("default", "test-delete")
		cmKey := types.NamespacedName{Name: cmName, Namespace: SystemNamespace}
		var cm corev1.ConfigMap

		if err := waitFor(ctx, k8sClient, cmKey, &cm, 10*time.Second); err != nil {
			t.Fatalf("ConfigMap not created: %v", err)
		}

		// Delete the policy.
		if err := k8sClient.Delete(ctx, ap); err != nil {
			t.Fatalf("failed to delete AegisPolicy: %v", err)
		}

		// Wait for ConfigMap to be deleted.
		if err := waitForDeletion(ctx, k8sClient, cmKey, &cm, 10*time.Second); err != nil {
			t.Fatal("ConfigMap was not cleaned up after policy deletion")
		}
	})
}

// waitFor polls until the object exists.
func waitFor(ctx context.Context, c client.Client, key types.NamespacedName, obj client.Object, timeout time.Duration) error {
	deadline := time.After(timeout)
	for {
		select {
		case <-deadline:
			return context.DeadlineExceeded
		case <-ctx.Done():
			return ctx.Err()
		default:
			if err := c.Get(ctx, key, obj); err == nil {
				return nil
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
}

// waitForCondition polls until the condition function returns true.
func waitForCondition(ctx context.Context, c client.Client, key types.NamespacedName, obj client.Object, timeout time.Duration, cond func() bool) error {
	deadline := time.After(timeout)
	for {
		select {
		case <-deadline:
			return context.DeadlineExceeded
		case <-ctx.Done():
			return ctx.Err()
		default:
			if err := c.Get(ctx, key, obj); err == nil && cond() {
				return nil
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
}

// waitForDeletion polls until the object no longer exists.
func waitForDeletion(ctx context.Context, c client.Client, key types.NamespacedName, obj client.Object, timeout time.Duration) error {
	deadline := time.After(timeout)
	for {
		select {
		case <-deadline:
			return context.DeadlineExceeded
		case <-ctx.Done():
			return ctx.Err()
		default:
			if err := c.Get(ctx, key, obj); apierrors.IsNotFound(err) {
				return nil
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
}
