// Package runsc exports a sandboxed container's runtime changes with gVisor's
// own tooling, on the node, without running anything inside the workload.
package runsc

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strings"

	"github.com/tomersein/gvisor-sbom/internal/clean"
)

type Exporter struct {
	Binary string
	// Root is the runsc state directory the containerd shim uses, e.g.
	// /run/containerd/runsc/k8s.io.
	Root string
}

var containerIDPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// ContainerID extracts the runtime's container ID from a pod's
// status.containerStatuses[].containerID ("containerd://<id>").
func ContainerID(statusID string) (string, error) {
	id, ok := strings.CutPrefix(statusID, "containerd://")
	if !ok || !containerIDPattern.MatchString(id) {
		return "", fmt.Errorf("unsupported container ID %q: node mode needs containerd", clean.Name(statusID))
	}
	return id, nil
}

// RootfsUpper writes the container's rootfs upper layer, everything changed
// since it started, as a tar archive to file. gVisor's Sentry serialises the
// layer itself, so the workload cannot substitute its own archive. Whiteout
// entries (character devices 0:0) mark deleted paths.
func (e Exporter) RootfsUpper(ctx context.Context, containerID, file string) error {
	cmd := exec.CommandContext(ctx, e.Binary, "--root", e.Root, "tar", "rootfs-upper", "--file", file, containerID)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("runsc tar rootfs-upper: %w: %s", err, clean.Message(strings.TrimSpace(string(out))))
	}
	return nil
}
