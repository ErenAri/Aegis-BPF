package fleet

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	v1alpha1 "github.com/ErenAri/aegis-operator/api/v1alpha1"
)

// fakeFactory returns a ClientFactory that always hands out the same
// pre-seeded fake client, regardless of which rest.Config is passed.
// Tests register one factory per cluster name via clusterFactories.
type clusterFactories map[string]client.Client

func (cf clusterFactories) factory(t *testing.T) ClientFactory {
	t.Helper()
	// The Aggregator passes the same rest.Config we attach to each
	// ClusterTarget, so we use the *Config pointer identity to
	// route to the right fake client.
	return func(cfg *rest.Config) (client.Client, error) {
		c, ok := cf[cfg.Host]
		if !ok {
			t.Fatalf("no fake client registered for cfg.Host=%q", cfg.Host)
		}
		return c, nil
	}
}

func newFakeClient(objs ...client.Object) client.Client {
	scheme := runtime.NewScheme()
	_ = v1alpha1.AddToScheme(scheme)
	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()
}

func policy(ns, name, mode, phase string, ready metav1.ConditionStatus, msg string) *v1alpha1.AegisPolicy {
	p := &v1alpha1.AegisPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:              name,
			Namespace:         ns,
			Generation:        2,
			CreationTimestamp: metav1.Time{Time: time.Now().Add(-3 * time.Hour)},
		},
		Spec: v1alpha1.AegisPolicySpec{Mode: mode},
		Status: v1alpha1.AegisPolicyStatus{
			Phase: phase,
			Conditions: []metav1.Condition{
				{Type: "Ready", Status: ready, Message: msg, LastTransitionTime: metav1.Now()},
			},
		},
	}
	return p
}

func clusterPolicy(name, mode, phase string, ready metav1.ConditionStatus) *v1alpha1.AegisClusterPolicy {
	return &v1alpha1.AegisClusterPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:              name,
			Generation:        1,
			CreationTimestamp: metav1.Time{Time: time.Now().Add(-30 * time.Minute)},
		},
		Spec: v1alpha1.AegisPolicySpec{Mode: mode},
		Status: v1alpha1.AegisPolicyStatus{
			Phase: phase,
			Conditions: []metav1.Condition{
				{Type: "Ready", Status: ready, LastTransitionTime: metav1.Now()},
			},
		},
	}
}

func TestCollectAggregatesAcrossClustersAndSorts(t *testing.T) {
	euClient := newFakeClient(
		policy("production", "block-files", "enforce", "Applied", metav1.ConditionTrue, ""),
		clusterPolicy("kernel-protect", "audit", "Applied", metav1.ConditionTrue),
	)
	usClient := newFakeClient(
		policy("production", "block-files", "enforce", "Pending", metav1.ConditionFalse, "ConfigMap missing"),
	)

	cf := clusterFactories{"prod-eu": euClient, "prod-us": usClient}
	agg := &Aggregator{NewClient: cf.factory(t)}

	res, err := agg.Collect(context.Background(),
		[]ClusterTarget{
			{Name: "prod-us", RESTConfig: &rest.Config{Host: "prod-us"}},
			{Name: "prod-eu", RESTConfig: &rest.Config{Host: "prod-eu"}},
		},
		Options{Timeout: 5 * time.Second},
	)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(res.Errors) != 0 {
		t.Fatalf("expected no per-cluster errors, got %v", res.Errors)
	}

	// Sorted: prod-eu first (cluster), then within-cluster by ns/name.
	if got, want := len(res.Rows), 3; got != want {
		t.Fatalf("rows: got %d, want %d", got, want)
	}
	if res.Rows[0].Cluster != "prod-eu" || res.Rows[0].Namespace != "" || res.Rows[0].Scope != "Cluster" {
		t.Errorf("first row should be prod-eu cluster-scoped policy; got %+v", res.Rows[0])
	}
	if res.Rows[1].Cluster != "prod-eu" || res.Rows[1].Namespace != "production" {
		t.Errorf("second row should be prod-eu namespaced policy; got %+v", res.Rows[1])
	}
	if res.Rows[2].Cluster != "prod-us" || res.Rows[2].Ready != string(metav1.ConditionFalse) {
		t.Errorf("third row should be prod-us namespaced policy with Ready=False; got %+v", res.Rows[2])
	}
	if res.Rows[2].Error != "ConfigMap missing" {
		t.Errorf("expected Error=%q, got %q", "ConfigMap missing", res.Rows[2].Error)
	}
}

func TestCollectErrorsAreScopedPerCluster(t *testing.T) {
	good := newFakeClient(policy("default", "p", "audit", "Applied", metav1.ConditionTrue, ""))
	cf := clusterFactories{"good": good}
	agg := &Aggregator{NewClient: func(cfg *rest.Config) (client.Client, error) {
		if cfg.Host == "broken" {
			return nil, errAsHostError("connection refused")
		}
		return cf["good"], nil
	}}

	res, err := agg.Collect(context.Background(),
		[]ClusterTarget{
			{Name: "broken", RESTConfig: &rest.Config{Host: "broken"}},
			{Name: "good", RESTConfig: &rest.Config{Host: "good"}},
		},
		Options{},
	)
	if err != nil {
		t.Fatalf("Collect should not fail when individual clusters fail; got %v", err)
	}
	if len(res.Rows) != 1 || res.Rows[0].Cluster != "good" {
		t.Fatalf("good cluster should still produce its row; got %+v", res.Rows)
	}
	if len(res.Errors) != 1 || res.Errors[0].Cluster != "broken" || res.Errors[0].Stage != "connect" {
		t.Fatalf("expected one connect error for 'broken'; got %+v", res.Errors)
	}
}

func TestCollectNamespaceFilterOnlyAffectsNamespaced(t *testing.T) {
	c := newFakeClient(
		policy("a", "p1", "audit", "Applied", metav1.ConditionTrue, ""),
		policy("b", "p2", "audit", "Applied", metav1.ConditionTrue, ""),
		clusterPolicy("c1", "audit", "Applied", metav1.ConditionTrue),
	)
	cf := clusterFactories{"only": c}
	agg := &Aggregator{NewClient: cf.factory(t)}

	res, err := agg.Collect(context.Background(),
		[]ClusterTarget{{Name: "only", RESTConfig: &rest.Config{Host: "only"}}},
		Options{Namespace: "a"},
	)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	// Expect: namespaced p1 (in ns "a") + cluster-scoped c1. Not p2.
	got := map[string]bool{}
	for _, r := range res.Rows {
		got[r.Name] = true
	}
	if !got["p1"] || !got["c1"] || got["p2"] {
		t.Fatalf("namespace filter wrong; rows = %+v", res.Rows)
	}
}

func TestCollectNoTargetsIsExplicitError(t *testing.T) {
	agg := NewAggregator()
	_, err := agg.Collect(context.Background(), nil, Options{})
	if err == nil {
		t.Fatal("expected error for empty targets, got nil")
	}
}

func TestExitCodeContract(t *testing.T) {
	tcs := []struct {
		name string
		res  Result
		want int
	}{
		{"all good", Result{Rows: []PolicyRow{{Ready: "True"}}}, 0},
		{"empty", Result{}, 0},
		{"one not ready", Result{Rows: []PolicyRow{{Ready: "True"}, {Ready: "False"}}}, 2},
		{"cluster failure outranks policy failure",
			Result{Rows: []PolicyRow{{Ready: "False"}}, Errors: []ClusterError{{Cluster: "x", Stage: "connect"}}}, 3},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			if got := ExitCode(tc.res); got != tc.want {
				t.Errorf("got %d, want %d", got, tc.want)
			}
		})
	}
}

func TestRenderTableContainsExpectedColumns(t *testing.T) {
	res := Result{Rows: []PolicyRow{{
		Cluster: "c1", Namespace: "ns", Name: "p", Scope: "Namespaced",
		Mode: "audit", Phase: "Applied", Ready: "True", Generation: 7,
		Age: time.Now().Add(-2 * time.Hour),
	}}}
	var buf bytes.Buffer
	if err := RenderTable(&buf, res); err != nil {
		t.Fatalf("RenderTable: %v", err)
	}
	s := buf.String()
	for _, want := range []string{"CLUSTER", "NAMESPACE", "NAME", "c1", "ns", "p", "Namespaced", "audit", "Applied"} {
		if !strings.Contains(s, want) {
			t.Errorf("table missing %q: %s", want, s)
		}
	}
}

func TestRenderJSONIsRoundTrippable(t *testing.T) {
	res := Result{
		Rows:   []PolicyRow{{Cluster: "c", Name: "p", Scope: "Cluster", Mode: "audit", Ready: "True"}},
		Errors: []ClusterError{{Cluster: "x", Stage: "connect", Message: "oops"}},
	}
	var buf bytes.Buffer
	if err := RenderJSON(&buf, res); err != nil {
		t.Fatalf("RenderJSON: %v", err)
	}
	var got Result
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got.Rows) != 1 || got.Rows[0].Name != "p" {
		t.Errorf("rows lost in roundtrip: %+v", got.Rows)
	}
	if len(got.Errors) != 1 || got.Errors[0].Stage != "connect" {
		t.Errorf("errors lost: %+v", got.Errors)
	}
}

// hostError carries the host name through into a ClientFactory error
// so the aggregator's connect-stage handler can format it without the
// test having to dig into wrapped errors.
type hostError string

func (e hostError) Error() string { return string(e) }
func errAsHostError(s string) error { return hostError(s) }
