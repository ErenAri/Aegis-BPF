package controllers

import (
	"testing"

	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1alpha1 "github.com/ErenAri/aegis-operator/api/v1alpha1"
)

func findCondition(status *v1alpha1.AegisPolicyStatus, condType string) *metav1.Condition {
	return apimeta.FindStatusCondition(status.Conditions, condType)
}

func TestMarkPolicyValid_setsPolicyValidTrue(t *testing.T) {
	status := &v1alpha1.AegisPolicyStatus{}
	markPolicyValid(status, 7)

	c := findCondition(status, v1alpha1.ConditionPolicyValid)
	if c == nil {
		t.Fatalf("expected PolicyValid condition to be present")
	}
	if c.Status != metav1.ConditionTrue {
		t.Errorf("expected PolicyValid=True, got %s", c.Status)
	}
	if c.Reason != v1alpha1.ReasonPolicyApplied {
		t.Errorf("expected reason %q, got %q", v1alpha1.ReasonPolicyApplied, c.Reason)
	}
	if c.ObservedGeneration != 7 {
		t.Errorf("expected ObservedGeneration=7, got %d", c.ObservedGeneration)
	}
}

func TestMarkPolicyInvalid_clearsReadyAndSetsReason(t *testing.T) {
	status := &v1alpha1.AegisPolicyStatus{}
	// Pretend Ready was True from a previous reconcile.
	markReady(status, 1, "previous reconcile")

	markPolicyInvalid(status, 2, v1alpha1.ReasonTranslationFailed, "bad spec")

	pv := findCondition(status, v1alpha1.ConditionPolicyValid)
	if pv == nil || pv.Status != metav1.ConditionFalse {
		t.Errorf("expected PolicyValid=False, got %v", pv)
	}
	r := findCondition(status, v1alpha1.ConditionReady)
	if r == nil || r.Status != metav1.ConditionFalse {
		t.Errorf("expected Ready=False after invalid spec, got %v", r)
	}
	if r.Reason != v1alpha1.ReasonTranslationFailed {
		t.Errorf("expected Ready reason %q, got %q",
			v1alpha1.ReasonTranslationFailed, r.Reason)
	}
}

func TestMarkReady_setsReadyTrueAndDegradedFalse(t *testing.T) {
	status := &v1alpha1.AegisPolicyStatus{}
	markDegraded(status, 1, "PreviousFlap", "stale")

	markReady(status, 5, "ConfigMap written")

	r := findCondition(status, v1alpha1.ConditionReady)
	if r == nil || r.Status != metav1.ConditionTrue {
		t.Errorf("expected Ready=True, got %v", r)
	}
	d := findCondition(status, v1alpha1.ConditionDegraded)
	if d == nil || d.Status != metav1.ConditionFalse {
		t.Errorf("expected Degraded cleared to False, got %v", d)
	}
	if r.ObservedGeneration != 5 {
		t.Errorf("expected ObservedGeneration=5 on Ready, got %d", r.ObservedGeneration)
	}
}

func TestMarkEnforceCapableUnknown_isUnknownNotFalse(t *testing.T) {
	// We deliberately default EnforceCapable to Unknown rather than False
	// because the operator does not yet observe per-node posture. This test
	// pins that contract — flipping it to False would silently regress
	// alerts that fire on EnforceCapable=False.
	status := &v1alpha1.AegisPolicyStatus{}
	markEnforceCapableUnknown(status, 3)

	c := findCondition(status, v1alpha1.ConditionEnforceCapable)
	if c == nil {
		t.Fatalf("expected EnforceCapable condition to be present")
	}
	if c.Status != metav1.ConditionUnknown {
		t.Errorf("expected EnforceCapable=Unknown, got %s", c.Status)
	}
	if c.Reason != v1alpha1.ReasonAwaitingNodePosture {
		t.Errorf("expected reason %q, got %q",
			v1alpha1.ReasonAwaitingNodePosture, c.Reason)
	}
}

func TestSetCondition_isIdempotentOnSameValue(t *testing.T) {
	// SetStatusCondition should not bump LastTransitionTime if neither
	// Status nor Reason changed. We rely on this so that frequent reconciles
	// don't cause spurious status updates.
	status := &v1alpha1.AegisPolicyStatus{}
	markReady(status, 1, "first")
	first := findCondition(status, v1alpha1.ConditionReady).LastTransitionTime

	markReady(status, 1, "first")
	second := findCondition(status, v1alpha1.ConditionReady).LastTransitionTime

	if !first.Equal(&second) {
		t.Errorf("expected idempotent set to preserve LastTransitionTime, got %v -> %v",
			first, second)
	}
}
