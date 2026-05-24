// Package console provides a lightweight web console for the aegis-operator,
// built with Go html/template + htmx + server-sent events.
package console

import (
	"sync"
)

// EventType identifies the kind of SSE event the browser should handle.
type EventType string

const (
	EventPolicyUpdate   EventType = "policyUpdate"
	EventReconcile      EventType = "reconcile"
	EventNodeStatus     EventType = "nodeStatus"
	EventStatsRefresh   EventType = "statsRefresh"
)

// Event is a single SSE message sent to connected browsers.
type Event struct {
	Type EventType
	HTML string
}

// Broker fans out events to all connected SSE clients.
type Broker struct {
	mu      sync.RWMutex
	clients map[chan Event]struct{}
}

// NewBroker creates a ready-to-use event broker.
func NewBroker() *Broker {
	return &Broker{
		clients: make(map[chan Event]struct{}),
	}
}

// Subscribe registers a new SSE client and returns its event channel.
func (b *Broker) Subscribe() chan Event {
	ch := make(chan Event, 32)
	b.mu.Lock()
	b.clients[ch] = struct{}{}
	b.mu.Unlock()
	return ch
}

// Unsubscribe removes a client channel and closes it.
func (b *Broker) Unsubscribe(ch chan Event) {
	b.mu.Lock()
	delete(b.clients, ch)
	b.mu.Unlock()
	close(ch)
}

// Publish sends an event to all connected clients. Slow clients that
// cannot keep up have the event dropped (non-blocking send).
func (b *Broker) Publish(evt Event) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	for ch := range b.clients {
		select {
		case ch <- evt:
		default:
		}
	}
}

// ClientCount returns the number of connected SSE clients.
func (b *Broker) ClientCount() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.clients)
}

// PublishReconcile implements controllers.EventPublisher, sending a reconcile
// event to all connected SSE clients. This bridges the controller loop to
// the browser without the controllers package importing the console package.
func (b *Broker) PublishReconcile(kind, name, phase, message string) {
	b.Publish(Event{
		Type: EventReconcile,
		HTML: kind + ": " + name + " → " + phase + " (" + message + ")",
	})
}
