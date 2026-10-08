// Command gvsbom extracts SBOMs from Kubernetes pods that run under gVisor.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	"github.com/tomersein/gvisor-sbom/internal/kube"
	"github.com/tomersein/gvisor-sbom/internal/report"
	"github.com/tomersein/gvisor-sbom/internal/sbomgen"
	"github.com/tomersein/gvisor-sbom/internal/scanner"
)

var version = "dev"

const (
	exitOK = iota
	exitError
	exitUsage
	exitDrift
)

func main() {
	os.Exit(run())
}

func run() int {
	var (
		sel         kube.Selector
		opts        scanner.Options
		kubeconfig  string
		kubeContext string
		maxRootfsMB int64
		failOnDrift bool
		jsonOut     bool
		showVersion bool
	)

	fs := flag.NewFlagSet("gvsbom", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: gvsbom [flags]\n\n"+
			"Builds two SBOMs for every running container in pods that use the gVisor\n"+
			"runtime class: one from the image the pod runs (by digest), and one from the\n"+
			"container's live filesystem, copied out through the sandbox. Reports the\n"+
			"packages that differ between them (runtime drift).\n\nFlags:\n")
		fs.PrintDefaults()
	}
	fs.StringVar(&sel.Namespace, "namespace", "", "namespace to scan (default: the kubeconfig namespace)")
	fs.StringVar(&sel.Namespace, "n", "", "shorthand for --namespace")
	fs.BoolVar(&sel.AllNamespaces, "all-namespaces", false, "scan every namespace")
	fs.BoolVar(&sel.AllNamespaces, "A", false, "shorthand for --all-namespaces")
	fs.StringVar(&sel.Pod, "pod", "", "scan only this pod")
	fs.StringVar(&sel.RuntimeClass, "runtime-class", "gvisor", "runtime class name that selects gVisor pods")
	fs.StringVar(&opts.Mode, "mode", scanner.ModeExec, "how to read runtime changes: \"exec\" runs tar inside each container; \"node\" runs on the node and exports the sandbox's upper layer with runsc")
	fs.StringVar(&sel.Node, "node", os.Getenv("NODE_NAME"), "node mode: the node this scanner runs on (default $NODE_NAME)")
	fs.StringVar(&opts.Runsc.Binary, "runsc", "runsc", "node mode: path to the runsc binary")
	fs.StringVar(&opts.Runsc.Root, "runsc-root", "/run/containerd/runsc/k8s.io", "node mode: runsc state directory used by the containerd shim")
	fs.StringVar(&kubeconfig, "kubeconfig", "", "path to the kubeconfig file (default: $KUBECONFIG or ~/.kube/config)")
	fs.StringVar(&kubeContext, "context", "", "kubeconfig context to use")
	fs.StringVar(&opts.OutputDir, "output-dir", "sbom-output", "directory for SBOMs and results")
	fs.StringVar(&opts.OutputDir, "o", "sbom-output", "shorthand for --output-dir")
	fs.Int64Var(&maxRootfsMB, "max-rootfs-mb", 4096, "stop copying a container filesystem larger than this")
	fs.IntVar(&opts.MaxEntries, "max-entries", 500_000, "stop copying a container filesystem with more files, directories and links than this")
	fs.DurationVar(&opts.Timeout, "timeout", 10*time.Minute, "give up on one container after this long")
	fs.BoolVar(&opts.SkipImage, "skip-image", false, "do not build the image SBOM")
	fs.BoolVar(&opts.SkipRuntime, "skip-runtime", false, "do not build the runtime SBOM")
	fs.BoolVar(&opts.KeepRootfs, "keep-rootfs", false, "keep the copied filesystem next to the SBOMs")
	fs.BoolVar(&opts.IncludeVolumes, "include-volumes", false, "also copy data volumes (emptyDir, PVC, ...); secret, configMap, projected and downwardAPI volumes are never copied")
	fs.BoolVar(&failOnDrift, "fail-on-drift", false, "exit with code 3 when any container differs from its image")
	fs.BoolVar(&jsonOut, "json", false, "print the results as JSON instead of a table")
	fs.BoolVar(&showVersion, "version", false, "print the version and exit")
	if err := fs.Parse(os.Args[1:]); err != nil {
		return exitUsage
	}
	if showVersion {
		fmt.Println("gvsbom", version)
		return exitOK
	}
	if opts.SkipImage && opts.SkipRuntime {
		fmt.Fprintln(os.Stderr, "gvsbom: --skip-image and --skip-runtime leave nothing to do")
		return exitUsage
	}
	switch opts.Mode {
	case scanner.ModeExec:
		sel.Node = ""
	case scanner.ModeNode:
		if sel.Node == "" {
			fmt.Fprintln(os.Stderr, "gvsbom: node mode needs --node or $NODE_NAME")
			return exitUsage
		}
		if opts.SkipImage {
			fmt.Fprintln(os.Stderr, "gvsbom: node mode merges runtime changes into the image SBOM, so --skip-image is not allowed")
			return exitUsage
		}
	default:
		fmt.Fprintf(os.Stderr, "gvsbom: unknown --mode %q (use exec or node)\n", opts.Mode)
		return exitUsage
	}
	opts.MaxRootfsBytes = maxRootfsMB << 20

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	client, err := kube.New(kubeconfig, kubeContext)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gvsbom:", err)
		return exitError
	}
	targets, err := client.Targets(ctx, sel)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gvsbom:", err)
		return exitError
	}
	if len(targets) == 0 {
		fmt.Fprintf(os.Stderr, "gvsbom: no running pods with runtime class %q found\n", sel.RuntimeClass)
		return exitOK
	}

	s := scanner.New(client, sbomgen.Generator{Tool: "gvsbom", Version: version}, opts, os.Stderr)
	var results []scanner.Result
	failed, drifted := false, false
	for _, t := range targets {
		r := s.Scan(ctx, t)
		results = append(results, r)
		failed = failed || len(r.Errors) > 0
		drifted = drifted || (r.Drift != nil && !r.Drift.Empty())
	}

	if b, err := json.MarshalIndent(results, "", "  "); err == nil {
		_ = os.WriteFile(filepath.Join(opts.OutputDir, "summary.json"), b, 0o644)
		if jsonOut {
			fmt.Println(string(b))
		}
	}
	if !jsonOut {
		fmt.Fprintln(os.Stderr)
		report.Print(os.Stdout, results)
		fmt.Fprintf(os.Stdout, "\nSBOMs written to %s/\n", opts.OutputDir)
	}

	switch {
	case failed:
		return exitError
	case failOnDrift && drifted:
		return exitDrift
	default:
		return exitOK
	}
}
