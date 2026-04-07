// Package controllers — shared helpers for populating
// AegisPolicyStatus.Conditions on both AegisPolicy and AegisClusterPolicy.
//
// The helpers wrap apimeta.SetStatusCondition so that the controllers stay
// readable and so the Reason/Type strings come from one place.
package controllers

import (
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1alpha1 "github.com/ErenAri/aegis-operator/api/v1alpha1"
)

// setCondition is a thin wrapper that records the observed generation and
// stamps the transition time. Callers should pass status as
// metav1.ConditionTrue / ConditionFalse / ConditionUnknown.
func setCondition(status *v1alpha1.AegisPolicyStatus, observedGeneration int64,
	condType string, condStatus metav1.ConditionStatus, reason, message string) {
	apimeta.SetStatusCondition(&status.Conditions, metav1.Condition{
		Type:               condType,
		Status:             condStatus,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: observedGeneration,
	})
}

// markPolicyValid sets PolicyValid=True with reason PolicyApplied. It does
// not by itself imply Ready — the caller is responsible for setting Ready
// after the ConfigMap write succeeds.
func markPolicyValid(status *v1alpha1.AegisPolicyStatus, gen int64) {
	setCondition(status, gen,
		v1alpha1.ConditionPolicyValid, metav1.ConditionTrue,
		v1alpha1.ReasonPolicyApplied, "Spec parsed and translated successfully")
}

// markPolicyInvalid sets PolicyValid=False and clears Ready, because an
// invalid spec cannot be ready by definition.
func markPolicyInvalid(status *v1alpha1.AegisPolicyStatus, gen int64, reason, message string) {
	setCondition(status, gen,
		v1alpha1.ConditionPolicyValid, metav1.ConditionFalse, reason, message)
	setCondition(status, gen,
		v1alpha1.ConditionReady, metav1.ConditionFalse, reason, message)
}

// markReady sets Ready=True and clears Degraded. Call this after the
// ConfigMap write has been confirmed by the API server.
func markReady(status *v1alpha1.AegisPolicyStatus, gen int64, message string) {
	setCondition(status, gen,
		v1alpha1.ConditionReady, metav1.ConditionTrue,
		v1alpha1.ReasonPolicyApplied, message)
	setCondition(status, gen,
		v1alpha1.ConditionDegraded, metav1.ConditionFalse,
		v1alpha1.ReasonPolicyApplied, "Reconcile succeeded")
}

// markDegraded sets Degraded=True with the given reason. The caller decides
// whether to also flip Ready=False — for transient errors that may resolve
// on requeue, leaving Ready in its previous state is often correct.
func markDegraded(status *v1alpha1.AegisPolicyStatus, gen int64, reason, message string) {
	setCondition(status, gen,
		v1alpha1.ConditionDegraded, metav1.ConditionTrue, reason, message)
}

// markEnforceCapableUnknown is the default value for EnforceCapable until a
// node-posture aggregator (future work) reports actual daemon capability.
// Setting Unknown rather than True/False is deliberate: the controller does
// not yet observe per-node posture, and surfacing that uncertainty to
// operators is more honest than guessing.
func markEnforceCapableUnknown(status *v1alpha1.AegisPolicyStatus, gen int64) {
	setCondition(status, gen,
		v1alpha1.ConditionEnforceCapable, metav1.ConditionUnknown,
		v1alpha1.ReasonAwaitingNodePosture,
		"Per-node enforcement capability is not yet observed by the operator; "+
			"check daemon logs and `aegisbpf posture` on each node")
}
