package controllers

// EventPublisher is an optional interface for publishing reconciliation events
// to the console SSE broker. Controllers that have a non-nil publisher will
// emit events on successful reconciliation or errors, enabling real-time
// dashboard updates without polling.
type EventPublisher interface {
	// PublishReconcile notifies connected console clients that a policy
	// reconciliation completed. The kind identifies the CRD type
	// ("AegisPolicy", "AegisClusterPolicy", or "MergedPolicy"), name
	// identifies the resource, and phase is "Applied" or "Error".
	PublishReconcile(kind, name, phase, message string)
}
