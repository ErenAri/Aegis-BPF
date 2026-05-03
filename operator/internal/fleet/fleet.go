// Package fleet provides a read-only multi-cluster aggregator for
// AegisPolicy and AegisClusterPolicy resources.
//
// The aggregator connects to each configured cluster via a separate
// kubeconfig, lists every AegisPolicy and AegisClusterPolicy it can
// see, and returns a flattened slice tagged with the cluster name.
// It does not write to any cluster, does not push policies, and does
// not require any new CRDs — it is a pure observability layer that
// closes the "no fleet view across clusters" gap from the Honest
// Limitations list while leaving the spoke-side reconciliation flow
// untouched.
package fleet

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/ErenAri/aegis-operator/api/v1alpha1"
)

// PolicyRow is the flat representation of a policy in the fleet
// table. Both AegisPolicy and AegisClusterPolicy collapse into this
// shape; Scope distinguishes them.
type PolicyRow struct {
	Cluster     string    `json:"cluster"`
	Namespace   string    `json:"namespace,omitempty"`
	Name        string    `json:"name"`
	Scope       string    `json:"scope"` // "Namespaced" or "Cluster"
	Mode        string    `json:"mode"`  // "enforce" / "audit"
	Phase       string    `json:"phase,omitempty"`
	Ready       string    `json:"ready"` // "True" / "False" / "Unknown" / "" if no Ready cond
	Generation  int64     `json:"generation"`
	AppliedNode int       `json:"appliedNodes,omitempty"`
	Age         time.Time `json:"createdAt"`
	// Error captures any per-policy translation/observation issue (taken
	// from the Ready condition's Message when Status != True).
	Error string `json:"error,omitempty"`
}

// ClusterError captures a cluster-level failure (kubeconfig load,
// connection refused, RBAC denial, CRD not installed, …). The
// aggregator never aborts on per-cluster failures: it records them
// here and continues to the next cluster.
type ClusterError struct {
	Cluster string `json:"cluster"`
	Stage   string `json:"stage"` // "kubeconfig" | "connect" | "list-namespaced" | "list-cluster"
	Message string `json:"message"`
}

// Result is the aggregated output of one Collect() call.
type Result struct {
	Rows   []PolicyRow    `json:"rows"`
	Errors []ClusterError `json:"errors,omitempty"`
}

// ClusterTarget is one cluster the aggregator should query. Either
// KubeconfigPath (a file on disk) or RESTConfig (an in-memory
// rest.Config — used by tests with envtest, or by callers that
// already loaded their config).
type ClusterTarget struct {
	Name           string
	KubeconfigPath string
	Context        string // optional kubeconfig context override
	RESTConfig     *rest.Config
}

// Options control aggregation behaviour.
type Options struct {
	// Namespace, when non-empty, scopes AegisPolicy listing to the
	// given namespace. AegisClusterPolicy listing is unaffected
	// (it's cluster-scoped by definition).
	Namespace string

	// Timeout per cluster. A slow or unreachable cluster doesn't
	// stall the rest of the fleet.
	Timeout time.Duration
}

// ClientFactory builds a controller-runtime client.Client from a
// rest.Config. Defaults to client.New with the v1alpha1 scheme; tests
// override this to plug in a fake client.
type ClientFactory func(cfg *rest.Config) (client.Client, error)

// Aggregator is the entry point. It is goroutine-safe.
type Aggregator struct {
	NewClient ClientFactory
}

// NewAggregator returns an Aggregator wired to the real
// controller-runtime client.
func NewAggregator() *Aggregator {
	return &Aggregator{NewClient: defaultClientFactory}
}

func defaultClientFactory(cfg *rest.Config) (client.Client, error) {
	scheme := runtime.NewScheme()
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		return nil, fmt.Errorf("register v1alpha1: %w", err)
	}
	return client.New(cfg, client.Options{Scheme: scheme})
}

// Collect queries every target and returns a flattened, sorted
// PolicyRow slice plus any per-cluster errors.
func (a *Aggregator) Collect(ctx context.Context, targets []ClusterTarget, opts Options) (Result, error) {
	if a.NewClient == nil {
		return Result{}, errors.New("fleet: ClientFactory is nil; use NewAggregator()")
	}
	if len(targets) == 0 {
		return Result{}, errors.New("fleet: no cluster targets supplied")
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}

	var rows []PolicyRow
	var errs []ClusterError

	for _, t := range targets {
		clusterRows, clusterErrs := a.collectOne(ctx, t, opts, timeout)
		rows = append(rows, clusterRows...)
		errs = append(errs, clusterErrs...)
	}

	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].Cluster != rows[j].Cluster {
			return rows[i].Cluster < rows[j].Cluster
		}
		if rows[i].Namespace != rows[j].Namespace {
			return rows[i].Namespace < rows[j].Namespace
		}
		return rows[i].Name < rows[j].Name
	})

	return Result{Rows: rows, Errors: errs}, nil
}

func (a *Aggregator) collectOne(parentCtx context.Context, t ClusterTarget, opts Options,
	timeout time.Duration) ([]PolicyRow, []ClusterError) {

	clusterName := t.Name
	if clusterName == "" {
		clusterName = "<unnamed>"
	}

	cfg := t.RESTConfig
	if cfg == nil {
		loaded, err := loadConfig(t.KubeconfigPath, t.Context)
		if err != nil {
			return nil, []ClusterError{{Cluster: clusterName, Stage: "kubeconfig", Message: err.Error()}}
		}
		cfg = loaded
	}

	c, err := a.NewClient(cfg)
	if err != nil {
		return nil, []ClusterError{{Cluster: clusterName, Stage: "connect", Message: err.Error()}}
	}

	ctx, cancel := context.WithTimeout(parentCtx, timeout)
	defer cancel()

	var rows []PolicyRow
	var errs []ClusterError

	listOpts := []client.ListOption{}
	if opts.Namespace != "" {
		listOpts = append(listOpts, client.InNamespace(opts.Namespace))
	}

	var nsList v1alpha1.AegisPolicyList
	if err := c.List(ctx, &nsList, listOpts...); err != nil {
		errs = append(errs, ClusterError{Cluster: clusterName, Stage: "list-namespaced", Message: err.Error()})
	} else {
		for i := range nsList.Items {
			rows = append(rows, rowFromNamespaced(clusterName, &nsList.Items[i]))
		}
	}

	var clList v1alpha1.AegisClusterPolicyList
	if err := c.List(ctx, &clList); err != nil {
		errs = append(errs, ClusterError{Cluster: clusterName, Stage: "list-cluster", Message: err.Error()})
	} else {
		for i := range clList.Items {
			rows = append(rows, rowFromCluster(clusterName, &clList.Items[i]))
		}
	}

	return rows, errs
}

func rowFromNamespaced(cluster string, p *v1alpha1.AegisPolicy) PolicyRow {
	r := PolicyRow{
		Cluster:     cluster,
		Namespace:   p.Namespace,
		Name:        p.Name,
		Scope:       "Namespaced",
		Mode:        p.Spec.Mode,
		Phase:       p.Status.Phase,
		Generation:  p.Generation,
		AppliedNode: p.Status.AppliedNodes,
		Age:         p.CreationTimestamp.Time,
	}
	r.Ready, r.Error = readyFromConditions(p.Status.Conditions)
	return r
}

func rowFromCluster(cluster string, p *v1alpha1.AegisClusterPolicy) PolicyRow {
	r := PolicyRow{
		Cluster:    cluster,
		Name:       p.Name,
		Scope:      "Cluster",
		Mode:       p.Spec.Mode,
		Phase:      p.Status.Phase,
		Generation: p.Generation,
		Age:        p.CreationTimestamp.Time,
	}
	r.Ready, r.Error = readyFromConditions(p.Status.Conditions)
	return r
}

// readyFromConditions extracts the Ready condition status and, when
// the policy is not Ready, the human-readable message so the table
// can show *why*.
func readyFromConditions(conds []metav1.Condition) (string, string) {
	for _, c := range conds {
		if c.Type == "Ready" {
			if c.Status != metav1.ConditionTrue {
				return string(c.Status), c.Message
			}
			return string(c.Status), ""
		}
	}
	return "", ""
}

func loadConfig(path, contextName string) (*rest.Config, error) {
	if path == "" {
		return nil, errors.New("kubeconfig path is empty")
	}
	loader := &clientcmd.ClientConfigLoadingRules{ExplicitPath: path}
	overrides := &clientcmd.ConfigOverrides{}
	if contextName != "" {
		overrides.CurrentContext = contextName
	}
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loader, overrides).ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("load kubeconfig %s: %w", path, err)
	}
	return cfg, nil
}
