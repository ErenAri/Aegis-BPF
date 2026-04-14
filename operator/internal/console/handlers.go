package console

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/ErenAri/aegis-operator/api/v1alpha1"
	"github.com/ErenAri/aegis-operator/internal/policy"
)

// handleDashboard renders the main dashboard page.
func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/console" && r.URL.Path != "/console/" {
		http.NotFound(w, r)
		return
	}

	data := s.gatherDashboardData(r.Context())
	data.Page = "dashboard"

	if isHTMX(r) {
		s.renderPartial(w, "dashboard", "dashboard_content", data)
		return
	}
	s.renderPage(w, "dashboard", data)
}

// handlePolicies renders the policies list page.
func (s *Server) handlePolicies(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/console/policies" {
		http.NotFound(w, r)
		return
	}

	data := s.gatherDashboardData(r.Context())
	data.Page = "policies"

	if isHTMX(r) {
		s.renderPartial(w, "policies", "policies_content", data)
		return
	}
	s.renderPage(w, "policies", data)
}

// handlePolicyDetail renders a single policy detail page.
// URL: /console/policies/{scope}/{namespace}/{name} or /console/policies/{scope}/{name}
func (s *Server) handlePolicyDetail(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/console/policies/")
	if path == "" || path == "/" {
		s.handlePolicies(w, r)
		return
	}

	parts := strings.SplitN(path, "/", 3)
	var scope, namespace, name string
	switch len(parts) {
	case 2:
		scope = parts[0]
		name = parts[1]
	case 3:
		scope = parts[0]
		namespace = parts[1]
		name = parts[2]
	default:
		http.NotFound(w, r)
		return
	}

	// Find the policy.
	policies := s.listAllPolicies(r.Context())
	var found *PolicySummary
	for i := range policies {
		p := &policies[i]
		scopeMatch := (scope == "cluster" && p.Scope == "Cluster") ||
			(scope == "namespaced" && p.Scope == "Namespaced")
		if scopeMatch && p.Name == name && p.Namespace == namespace {
			found = p
			break
		}
	}

	if found == nil {
		http.NotFound(w, r)
		return
	}

	// Fetch the full spec for INI preview.
	var iniPreview string
	spec := s.fetchPolicySpec(r.Context(), found.Scope, found.Namespace, found.Name)
	if spec != nil {
		result, err := policy.TranslateToINI(*spec)
		if err == nil {
			iniPreview = result.INI
		}
	}

	detailData := struct {
		Page       string
		Policy     PolicySummary
		INIPreview string
		Spec       *v1alpha1.AegisPolicySpec
	}{
		Page:       "policies",
		Policy:     *found,
		INIPreview: iniPreview,
		Spec:       spec,
	}

	if isHTMX(r) {
		s.renderPartial(w, "policy_detail", "policy_detail_content", detailData)
		return
	}
	s.renderPage(w, "policy_detail", detailData)
}

// handleNodes renders the nodes/daemon status page.
func (s *Server) handleNodes(w http.ResponseWriter, r *http.Request) {
	data := s.gatherDashboardData(r.Context())
	data.Page = "nodes"

	if isHTMX(r) {
		s.renderPartial(w, "nodes", "nodes_content", data)
		return
	}
	s.renderPage(w, "nodes", data)
}

// handleSSE streams server-sent events to the browser.
func (s *Server) handleSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	ch := s.broker.Subscribe()
	defer s.broker.Unsubscribe(ch)

	// Send initial keepalive.
	fmt.Fprintf(w, ": keepalive\n\n")
	flusher.Flush()

	// Periodic heartbeat to detect dead connections.
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case evt, ok := <-ch:
			if !ok {
				return
			}
			// SSE wire format: event name + data lines.
			data := strings.ReplaceAll(evt.HTML, "\n", "\ndata: ")
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", evt.Type, data)
			flusher.Flush()
		case <-ticker.C:
			fmt.Fprintf(w, ": heartbeat\n\n")
			flusher.Flush()
		}
	}
}

// handlePolicyTablePartial renders just the policy table body (for htmx polling).
func (s *Server) handlePolicyTablePartial(w http.ResponseWriter, r *http.Request) {
	data := s.gatherDashboardData(r.Context())
	s.renderPartial(w, "dashboard", "policy_table", data)
}

// handleStatsPartial renders just the stats cards (for htmx polling).
func (s *Server) handleStatsPartial(w http.ResponseWriter, r *http.Request) {
	data := s.gatherDashboardData(r.Context())
	s.renderPartial(w, "dashboard", "stats_cards", data)
}

// fetchPolicySpec fetches the full AegisPolicySpec for a given policy.
func (s *Server) fetchPolicySpec(ctx context.Context, scope, namespace, name string) *v1alpha1.AegisPolicySpec {
	switch scope {
	case "Cluster":
		var p v1alpha1.AegisClusterPolicy
		if err := s.client.Get(ctx, clientKey(name, ""), &p); err != nil {
			return nil
		}
		return &p.Spec
	case "Namespaced":
		var p v1alpha1.AegisPolicy
		if err := s.client.Get(ctx, clientKey(name, namespace), &p); err != nil {
			return nil
		}
		return &p.Spec
	}
	return nil
}

func clientKey(name, namespace string) client.ObjectKey {
	return client.ObjectKey{Name: name, Namespace: namespace}
}

func isHTMX(r *http.Request) bool {
	return r.Header.Get("HX-Request") == "true"
}

func (s *Server) renderPage(w http.ResponseWriter, page string, data any) {
	t := s.templates.Lookup(page)
	if t == nil {
		http.Error(w, "unknown page: "+page, http.StatusInternalServerError)
		return
	}
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, page, data); err != nil {
		http.Error(w, "template error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	buf.WriteTo(w)
}

func (s *Server) renderPartial(w http.ResponseWriter, page, name string, data any) {
	t := s.templates.Lookup(page)
	if t == nil {
		http.Error(w, "unknown page: "+page, http.StatusInternalServerError)
		return
	}
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, name, data); err != nil {
		http.Error(w, "template error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	buf.WriteTo(w)
}

// RenderPartialToString renders a named template to a string (used by reconcilers
// to generate SSE payloads). Uses the dashboard page clone for shared partials.
func (s *Server) RenderPartialToString(name string, data any) string {
	t := s.templates.Lookup("dashboard")
	if t == nil {
		return fmt.Sprintf(`<span class="text-red-500">render error: no dashboard template</span>`)
	}
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, name, data); err != nil {
		return fmt.Sprintf(`<span class="text-red-500">render error: %v</span>`, err)
	}
	return buf.String()
}

