// Package report prints scan results for people.
package report

import (
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/tomersein/gvisor-sbom/internal/clean"
	"github.com/tomersein/gvisor-sbom/internal/scanner"
)

// Print writes results for a terminal. Package names, versions, paths and
// error text all originate in the scanned workload, so every one of them goes
// through clean before it is printed.
func Print(w io.Writer, results []scanner.Result) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "CONTAINER\tIMAGE PKGS\tRUNTIME PKGS\tADDED\tREMOVED\tCHANGED\tSTATUS")
	for _, r := range results {
		added, removed, changed := "-", "-", "-"
		if r.Drift != nil {
			added = fmt.Sprint(len(r.Drift.Added))
			removed = fmt.Sprint(len(r.Drift.Removed))
			changed = fmt.Sprint(len(r.Drift.Changed))
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			r.Target, count(r.ImageSBOM, r.ImagePackages), count(r.RuntimeSBOM, r.RuntimePackages),
			added, removed, changed, status(r))
	}
	tw.Flush()

	for _, r := range results {
		if r.Drift == nil && len(r.Errors) == 0 && len(r.Warnings) == 0 {
			continue
		}
		fmt.Fprintf(w, "\n%s\n", r.Target)
		if r.ImageRef != "" {
			fmt.Fprintf(w, "  image:   %s (%s)\n", clean.Name(r.ImageRef), clean.Name(r.Platform))
		}
		if r.Drift != nil {
			for _, p := range r.Drift.Added {
				fmt.Fprintf(w, "  + %s %s (%s)\n", clean.Name(p.Name), clean.Name(p.Version), clean.Name(p.Type))
			}
			for _, p := range r.Drift.Removed {
				fmt.Fprintf(w, "  - %s %s (%s)\n", clean.Name(p.Name), clean.Name(p.Version), clean.Name(p.Type))
			}
			for _, c := range r.Drift.Changed {
				fmt.Fprintf(w, "  ~ %s %s -> %s (%s)\n", clean.Name(c.Name), clean.Name(c.FromVersion), clean.Name(c.ToVersion), clean.Name(c.Type))
			}
			if r.Drift.Empty() && len(r.NotCovered) > 0 {
				fmt.Fprintln(w, "  no drift in the container's root filesystem")
			} else if r.Drift.Empty() {
				fmt.Fprintln(w, "  no drift: the running container matches its image")
			}
		}
		for _, e := range r.Excluded {
			if e.Reason != "kernel view" {
				fmt.Fprintf(w, "  not copied: %s (%s)\n", clean.Message(e.Path), e.Reason)
			}
		}
		for _, m := range r.NotCovered {
			fmt.Fprintf(w, "  not covered: %s\n", clean.Message(m))
		}
		for _, m := range r.Warnings {
			fmt.Fprintf(w, "  warning: %s\n", clean.Message(m))
		}
		for _, m := range r.Errors {
			fmt.Fprintf(w, "  error: %s\n", clean.Message(m))
		}
	}
}

func count(path string, n int) string {
	if path == "" {
		return "-"
	}
	return fmt.Sprint(n)
}

func status(r scanner.Result) string {
	switch {
	case len(r.Errors) > 0:
		return "error"
	case r.Drift != nil && !r.Drift.Empty():
		return "drift"
	case r.RuntimeUnavailable:
		return "image only"
	case len(r.Warnings) > 0:
		return fmt.Sprintf("ok (%d warnings)", len(r.Warnings))
	default:
		return "ok"
	}
}
