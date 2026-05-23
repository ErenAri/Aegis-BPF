package controllers

import (
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

var (
	// policyReconcileTotal counts reconciliation attempts by result.
	policyReconcileTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "aegis",
			Subsystem: "operator",
			Name:      "policy_reconcile_total",
			Help:      "Total policy reconciliation attempts by outcome.",
		},
		[]string{"outcome"}, // "success", "error"
	)

	// policyTranslateDuration tracks policy translation latency.
	policyTranslateDuration = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: "aegis",
			Subsystem: "operator",
			Name:      "policy_translate_duration_seconds",
			Help:      "Time spent translating AegisPolicy CRD to INI/next format.",
			Buckets:   prometheus.DefBuckets,
		},
	)

	// activePolicies tracks the number of active AegisPolicy resources.
	activePolicies = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "aegis",
			Subsystem: "operator",
			Name:      "active_policies",
			Help:      "Number of AegisPolicy resources currently being reconciled.",
		},
	)

	// configMapWriteErrors counts ConfigMap write failures.
	configMapWriteErrors = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "aegis",
			Subsystem: "operator",
			Name:      "configmap_write_errors_total",
			Help:      "Total ConfigMap create/update failures.",
		},
	)

	// agentSyncTotal counts agent sync attempts by outcome.
	agentSyncTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "aegis",
			Subsystem: "operator",
			Name:      "agent_sync_total",
			Help:      "Total agent sync attempts by outcome.",
		},
		[]string{"outcome"},
	)

	// agentSyncNodesApplied tracks number of nodes successfully synced.
	agentSyncNodesApplied = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "aegis",
			Subsystem: "operator",
			Name:      "agent_sync_nodes_applied",
			Help:      "Number of nodes with successfully applied agent rules.",
		},
	)
)

func init() {
	metrics.Registry.MustRegister(
		policyReconcileTotal,
		policyTranslateDuration,
		activePolicies,
		configMapWriteErrors,
		agentSyncTotal,
		agentSyncNodesApplied,
	)
}
