package fleet

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"
)

// RenderTable writes a human-readable, tab-separated table of the
// aggregated rows to w, followed by a "FLEET ERRORS" section if any
// per-cluster errors were recorded.
func RenderTable(w io.Writer, res Result) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "CLUSTER\tNAMESPACE\tNAME\tSCOPE\tMODE\tPHASE\tREADY\tGEN\tNODES\tAGE"); err != nil {
		return err
	}
	for _, r := range res.Rows {
		ns := r.Namespace
		if ns == "" {
			ns = "-"
		}
		ready := r.Ready
		if ready == "" {
			ready = "-"
		}
		phase := r.Phase
		if phase == "" {
			phase = "-"
		}
		nodes := "-"
		if r.AppliedNode > 0 {
			nodes = fmt.Sprintf("%d", r.AppliedNode)
		}
		if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%d\t%s\t%s\n",
			r.Cluster, ns, r.Name, r.Scope, r.Mode, phase, ready, r.Generation, nodes, formatAge(r.Age)); err != nil {
			return err
		}
	}
	if err := tw.Flush(); err != nil {
		return err
	}

	if len(res.Errors) > 0 {
		if _, err := fmt.Fprintln(w, "\nFLEET ERRORS:"); err != nil {
			return err
		}
		for _, e := range res.Errors {
			if _, err := fmt.Fprintf(w, "  %s [%s]: %s\n", e.Cluster, e.Stage, e.Message); err != nil {
				return err
			}
		}
	}
	return nil
}

// RenderJSON writes a stable JSON object {rows, errors} to w. The
// caller is responsible for newline handling at the end of the
// stream.
func RenderJSON(w io.Writer, res Result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(res)
}

// formatAge produces a kubectl-style relative age string ("5m",
// "3h", "12d"). An empty / zero timestamp prints "-" so the table
// stays aligned.
func formatAge(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}

// ExitCode returns a deterministic exit code:
//   - 0 when every cluster succeeded and every Ready condition is True or absent
//   - 2 when at least one row reports Ready=False
//   - 3 when at least one cluster failed (kubeconfig/connect/list)
//
// Useful for CI fleet checks. Cluster failure trumps policy failure
// so operators see infrastructure issues first.
func ExitCode(res Result) int {
	if len(res.Errors) > 0 {
		return 3
	}
	for _, r := range res.Rows {
		if strings.EqualFold(r.Ready, "False") {
			return 2
		}
	}
	return 0
}
