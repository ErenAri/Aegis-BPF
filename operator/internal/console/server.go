package console

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// Server is the web console HTTP server. It implements the controller-runtime
// Runnable interface so it can be added to the manager via mgr.Add().
type Server struct {
	client    client.Client
	addr      string
	broker    *Broker
	templates *TemplateSet
}

// NewServer creates a new console server.
func NewServer(c client.Client, addr string, broker *Broker) (*Server, error) {
	tmpl, err := parseTemplates()
	if err != nil {
		return nil, fmt.Errorf("parsing console templates: %w", err)
	}
	return &Server{
		client:    c,
		addr:      addr,
		broker:    broker,
		templates: tmpl,
	}, nil
}

// Start begins serving the web console. Blocks until ctx is cancelled.
func (s *Server) Start(ctx context.Context) error {
	logger := log.FromContext(ctx).WithName("console")

	mux := http.NewServeMux()

	// Static assets (htmx, sse.js).
	sub, err := staticFS()
	if err != nil {
		return fmt.Errorf("console static fs: %w", err)
	}
	mux.Handle("/console/static/", http.StripPrefix("/console/static/", http.FileServer(http.FS(sub))))

	// Pages.
	mux.HandleFunc("/console", s.handleDashboard)
	mux.HandleFunc("/console/", s.handleDashboard)
	mux.HandleFunc("/console/policies", s.handlePolicies)
	mux.HandleFunc("/console/policies/", s.handlePolicyDetail)
	mux.HandleFunc("/console/nodes", s.handleNodes)

	// API / SSE.
	mux.HandleFunc("/console/events", s.handleSSE)

	// htmx partials.
	mux.HandleFunc("/console/partials/policy-table", s.handlePolicyTablePartial)
	mux.HandleFunc("/console/partials/stats", s.handleStatsPartial)

	// Redirect root to console.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/console", http.StatusFound)
			return
		}
		http.NotFound(w, r)
	})

	srv := &http.Server{
		Addr:              s.addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(shutdownCtx)
	}()

	logger.Info("Starting web console", "addr", s.addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// NeedLeaderElection returns false — the console serves on all replicas.
func (s *Server) NeedLeaderElection() bool { return false }
