// Command aegisfleet aggregates AegisPolicy / AegisClusterPolicy
// status across multiple Kubernetes clusters, providing a read-only
// fleet view that closes the "no fleet view across clusters" gap
// from the Honest Limitations list.
//
// Usage:
//
//	aegisfleet --kubeconfig-dir=/etc/aegisfleet/kubeconfigs
//	aegisfleet --kubeconfig=prod-eu=/etc/k/eu --kubeconfig=prod-us=/etc/k/us
//	aegisfleet --kubeconfig-dir=… --output=json
//
// Exit codes:
//
//	0 everything Ready (or no Ready condition recorded)
//	2 at least one policy reports Ready=False
//	3 at least one cluster failed (kubeconfig / connect / list)
//
// The tool never writes to any cluster.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ErenAri/aegis-operator/internal/fleet"
)

type stringSlice []string

func (s *stringSlice) String() string         { return strings.Join(*s, ",") }
func (s *stringSlice) Set(v string) error     { *s = append(*s, v); return nil }

func main() {
	var (
		kubeconfigDir string
		kubeconfigs   stringSlice
		namespace     string
		output        string
		timeout       time.Duration
	)

	flag.StringVar(&kubeconfigDir, "kubeconfig-dir", "",
		"Directory of per-cluster kubeconfig files (cluster name = filename without extension).")
	flag.Var(&kubeconfigs, "kubeconfig",
		"Repeated. Either path/to/kubeconfig or name=path/to/kubeconfig.")
	flag.StringVar(&namespace, "namespace", "",
		"Limit AegisPolicy listing to this namespace (cluster-scoped policies are unaffected).")
	flag.StringVar(&output, "output", "table",
		"Output format: table | json")
	flag.DurationVar(&timeout, "timeout", 15*time.Second,
		"Per-cluster query timeout.")
	flag.Parse()

	targets, err := fleet.DiscoverTargets(kubeconfigDir, kubeconfigs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "aegisfleet: %v\n", err)
		os.Exit(1)
	}
	if len(targets) == 0 {
		fmt.Fprintln(os.Stderr,
			"aegisfleet: no clusters configured. Pass --kubeconfig-dir=<dir> or repeat --kubeconfig=<path>.")
		os.Exit(1)
	}

	agg := fleet.NewAggregator()
	res, err := agg.Collect(context.Background(), targets, fleet.Options{
		Namespace: namespace,
		Timeout:   timeout,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "aegisfleet: %v\n", err)
		os.Exit(1)
	}

	switch output {
	case "json":
		if err := fleet.RenderJSON(os.Stdout, res); err != nil {
			fmt.Fprintf(os.Stderr, "aegisfleet: render: %v\n", err)
			os.Exit(1)
		}
	case "table", "":
		if err := fleet.RenderTable(os.Stdout, res); err != nil {
			fmt.Fprintf(os.Stderr, "aegisfleet: render: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "aegisfleet: unknown --output=%s (want table | json)\n", output)
		os.Exit(1)
	}

	os.Exit(fleet.ExitCode(res))
}
