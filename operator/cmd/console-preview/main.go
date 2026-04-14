// Command console-preview runs the web console with mock data for UI development.
// Usage: go run ./cmd/console-preview
package main

import (
	"bytes"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"time"

	"github.com/ErenAri/aegis-operator/internal/console"
)

func main() {
	tmpl, staticSub := console.PreviewAssets()

	now := time.Now()
	fiveMin := now.Add(-5 * time.Minute)
	twoHours := now.Add(-2 * time.Hour)

	mockDashboard := console.DashboardData{
		Page:            "dashboard",
		TotalPolicies:   4,
		EnforceCount:    1,
		AuditCount:      3,
		AppliedCount:    3,
		ErrorCount:      1,
		DeprecatedCount: 1,
		AllowRuleCount:  1,
		BlockRuleCount:  3,
		RunningPods:     2,
		ActiveClients:   1,
		Now:             now,
		Policies: []console.PolicySummary{
			{Name: "block-sensitive-files", Namespace: "production", Scope: "Namespaced", Mode: "enforce", Phase: "Applied", Hash: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4", FileRules: 3, HasBlock: true, LastApplied: &fiveMin, Generation: 2, Conditions: []console.ConditionView{
				{Type: "Ready", Status: "True", Reason: "PolicyApplied", Message: "Policy translated and ConfigMap written", Ago: "5m ago"},
				{Type: "PolicyValid", Status: "True", Reason: "PolicyApplied", Message: "Spec parsed and translated successfully", Ago: "5m ago"},
				{Type: "EnforceCapable", Status: "Unknown", Reason: "AwaitingNodePosture", Message: "Per-node enforcement capability is not yet observed", Ago: "5m ago"},
			}},
			{Name: "network-lockdown", Namespace: "production", Scope: "Namespaced", Mode: "audit", Phase: "Applied", Hash: "b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5", NetworkRules: 5, HasBlock: true, HasAllow: true, LastApplied: &twoHours, Generation: 4},
			{Name: "cluster-kernel-hardening", Scope: "Cluster", Mode: "audit", Phase: "Applied", Hash: "c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6", KernelRules: 3, HasBlock: true, LastApplied: &fiveMin, Generation: 1},
			{Name: "legacy-policy", Namespace: "staging", Scope: "Namespaced", Mode: "audit", Phase: "Error", Message: "Translation failed: empty spec", Deprecated: true, Generation: 1},
		},
		DaemonPods: []console.DaemonPodView{
			{Name: "aegisbpf-daemon-x7k2p", Node: "node-1", Phase: "Running", Ready: true, Restarts: 0, Age: "3d ago", IP: "10.244.1.15"},
			{Name: "aegisbpf-daemon-m9n3q", Node: "node-2", Phase: "Running", Ready: true, Restarts: 2, Age: "3d ago", IP: "10.244.2.22"},
		},
	}

	mockPolicies := mockDashboard
	mockPolicies.Page = "policies"

	mockNodes := mockDashboard
	mockNodes.Page = "nodes"

	mux := http.NewServeMux()
	mux.Handle("/console/static/", http.StripPrefix("/console/static/", http.FileServer(http.FS(staticSub))))

	// Mock SSE endpoint — sends keepalives so htmx-ext-sse doesn't reconnect-flood.
	mux.HandleFunc("/console/events", func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "no flusher", 500)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		fmt.Fprintf(w, ": keepalive\n\n")
		flusher.Flush()
		<-r.Context().Done()
	})

	// Mock partial endpoints for htmx polling.
	mux.HandleFunc("/console/partials/stats", func(w http.ResponseWriter, r *http.Request) {
		renderPartial(w, tmpl, "dashboard", "stats_cards", mockDashboard)
	})
	mux.HandleFunc("/console/partials/policy-table", func(w http.ResponseWriter, r *http.Request) {
		renderPartial(w, tmpl, "dashboard", "policy_table", mockDashboard)
	})

	// Pages.
	mux.HandleFunc("/console", func(w http.ResponseWriter, r *http.Request) {
		render(w, tmpl, "dashboard", mockDashboard)
	})
	mux.HandleFunc("/console/", func(w http.ResponseWriter, r *http.Request) {
		render(w, tmpl, "dashboard", mockDashboard)
	})
	mux.HandleFunc("/console/policies", func(w http.ResponseWriter, r *http.Request) {
		render(w, tmpl, "policies", mockPolicies)
	})
	mux.HandleFunc("/console/policies/", func(w http.ResponseWriter, r *http.Request) {
		// Mock policy detail — always show first policy.
		detailData := struct {
			Page       string
			Policy     console.PolicySummary
			INIPreview string
			Spec       interface{}
		}{
			Page:       "policies",
			Policy:     mockDashboard.Policies[0],
			INIPreview: "[global]\nmode = enforce\n\n[file_deny]\n/etc/shadow = block\n/etc/passwd = block\n/etc/gshadow = block\n",
		}
		render(w, tmpl, "policy_detail", detailData)
	})
	mux.HandleFunc("/console/nodes", func(w http.ResponseWriter, r *http.Request) {
		render(w, tmpl, "nodes", mockNodes)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/console", http.StatusFound)
	})

	fmt.Println("Preview: http://localhost:9090/console")
	if err := http.ListenAndServe(":9090", mux); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func render(w http.ResponseWriter, ts *console.TemplateSet, page string, data any) {
	t := ts.Lookup(page)
	if t == nil {
		http.Error(w, "unknown page: "+page, 500)
		return
	}
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, page, data); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	buf.WriteTo(w)
}

func renderPartial(w http.ResponseWriter, ts *console.TemplateSet, page, name string, data any) {
	t := ts.Lookup(page)
	if t == nil {
		http.Error(w, "unknown page: "+page, 500)
		return
	}
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, name, data); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	buf.WriteTo(w)
}

// Ensure the types are accessible for mock data.
var _ fs.FS
