// Package identity resolves Kubernetes pod identities from cgroup IDs and
// container metadata, maintaining a cache for event enrichment by the daemon.
package identity

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	// IdentityCacheConfigMap is the name of the ConfigMap holding identity mappings.
	IdentityCacheConfigMap = "aegis-identity-cache"

	// IdentityCacheNamespace is the namespace for the identity cache.
	IdentityCacheNamespace = "aegisbpf-system"

	// IdentityCacheKey is the data key in the ConfigMap.
	IdentityCacheKey = "identity-cache.json"
)

// PodIdentity holds the Kubernetes identity of a pod.
type PodIdentity struct {
	PodName        string            `json:"pod"`
	Namespace      string            `json:"namespace"`
	ServiceAccount string            `json:"serviceAccount"`
	ContainerID    string            `json:"containerID,omitempty"`
	Labels         map[string]string `json:"labels,omitempty"`
	NodeName       string            `json:"nodeName,omitempty"`
}

// Resolver watches Kubernetes pods and maintains a container-to-identity mapping.
type Resolver struct {
	client   client.Client
	mu       sync.RWMutex
	cache    map[string]PodIdentity // containerID → PodIdentity
	interval time.Duration
}

// NewResolver creates a new identity resolver.
func NewResolver(c client.Client, refreshInterval time.Duration) *Resolver {
	return &Resolver{
		client:   c,
		cache:    make(map[string]PodIdentity),
		interval: refreshInterval,
	}
}

// Start begins the periodic identity cache refresh loop.
func (r *Resolver) Start(ctx context.Context) error {
	logger := log.FromContext(ctx).WithName("identity-resolver")
	logger.Info("Starting identity resolver", "interval", r.interval)

	// Initial scan.
	if err := r.refresh(ctx); err != nil {
		logger.Error(err, "Initial identity scan failed")
	}

	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			logger.Info("Identity resolver stopping")
			return nil
		case <-ticker.C:
			if err := r.refresh(ctx); err != nil {
				logger.Error(err, "Identity refresh failed")
			}
		}
	}
}

// refresh scans all pods and rebuilds the identity cache.
func (r *Resolver) refresh(ctx context.Context) error {
	logger := log.FromContext(ctx).WithName("identity-resolver")

	var podList corev1.PodList
	if err := r.client.List(ctx, &podList); err != nil {
		return fmt.Errorf("listing pods: %w", err)
	}

	newCache := make(map[string]PodIdentity, len(podList.Items))
	for i := range podList.Items {
		pod := &podList.Items[i]
		identity := PodIdentity{
			PodName:        pod.Name,
			Namespace:      pod.Namespace,
			ServiceAccount: pod.Spec.ServiceAccountName,
			Labels:         pod.Labels,
			NodeName:       pod.Spec.NodeName,
		}

		// Extract container IDs from pod status.
		for _, cs := range pod.Status.ContainerStatuses {
			cid := extractContainerID(cs.ContainerID)
			if cid != "" {
				identity.ContainerID = cid
				newCache[cid] = identity
			}
		}
		for _, cs := range pod.Status.InitContainerStatuses {
			cid := extractContainerID(cs.ContainerID)
			if cid != "" {
				identity.ContainerID = cid
				newCache[cid] = identity
			}
		}
	}

	r.mu.Lock()
	r.cache = newCache
	r.mu.Unlock()

	// Write cache to ConfigMap for the C++ daemon to read.
	if err := r.writeConfigMap(ctx, newCache); err != nil {
		logger.Error(err, "Failed to write identity cache ConfigMap")
		return err
	}

	logger.V(1).Info("Identity cache refreshed", "containers", len(newCache))
	return nil
}

// writeConfigMap writes the identity cache to a ConfigMap.
func (r *Resolver) writeConfigMap(ctx context.Context, cache map[string]PodIdentity) error {
	data, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling identity cache: %w", err)
	}

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      IdentityCacheConfigMap,
			Namespace: IdentityCacheNamespace,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "aegis-operator",
				"aegisbpf.io/component":        "identity-cache",
			},
		},
		Data: map[string]string{
			IdentityCacheKey: string(data),
		},
	}

	var existing corev1.ConfigMap
	err = r.client.Get(ctx, types.NamespacedName{
		Name:      IdentityCacheConfigMap,
		Namespace: IdentityCacheNamespace,
	}, &existing)

	if errors.IsNotFound(err) {
		return r.client.Create(ctx, cm)
	}
	if err != nil {
		return err
	}

	existing.Data = cm.Data
	return r.client.Update(ctx, &existing)
}

// Lookup returns the identity for a given container ID.
func (r *Resolver) Lookup(containerID string) (PodIdentity, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	id, ok := r.cache[containerID]
	return id, ok
}

// Size returns the number of cached identities.
func (r *Resolver) Size() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.cache)
}

// extractContainerID parses the container ID from a CRI container ID string.
// Format: "containerd://abc123..." or "docker://abc123..."
func extractContainerID(criID string) string {
	if criID == "" {
		return ""
	}
	// Find the last "/" and take everything after it.
	for i := len(criID) - 1; i >= 0; i-- {
		if criID[i] == '/' {
			return criID[i+1:]
		}
	}
	return criID
}
