// Package scanner builds an image SBOM and a runtime SBOM for each sandboxed
// container and reports the drift between them.
package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/anchore/syft/syft/sbom"
	utilexec "k8s.io/client-go/util/exec"

	"github.com/tomersein/gvisor-sbom/internal/clean"
	"github.com/tomersein/gvisor-sbom/internal/drift"
	"github.com/tomersein/gvisor-sbom/internal/kube"
	"github.com/tomersein/gvisor-sbom/internal/overlay"
	"github.com/tomersein/gvisor-sbom/internal/rootfs"
	"github.com/tomersein/gvisor-sbom/internal/runsc"
	"github.com/tomersein/gvisor-sbom/internal/sbomgen"
)

const (
	// ModeExec copies the container's filesystem out through `tar` run
	// inside the sandbox. It sees everything the workload sees, including
	// /tmp and volumes, but the workload controls the archive.
	ModeExec = "exec"
	// ModeNode exports the sandbox's rootfs upper layer with runsc on the
	// node and merges it into the image SBOM. gVisor produces the archive and
	// it holds only what changed, but in-memory mounts and volumes are not
	// part of it.
	ModeNode = "node"
)

var ErrNoTar = errors.New("no tar binary in the container (distroless image?); a runtime SBOM needs `runsc tar rootfs-upper` on the node instead")

type Options struct {
	Mode           string
	Runsc          runsc.Exporter
	OutputDir      string
	MaxRootfsBytes int64
	MaxEntries     int
	// Timeout bounds the whole scan of one container, so a slow stream or a
	// parser stuck on a crafted file cannot hang the scanner.
	Timeout     time.Duration
	SkipImage   bool
	SkipRuntime bool
	KeepRootfs  bool
	// IncludeVolumes copies data volumes too. Credential volumes are never copied.
	IncludeVolumes bool
}

type Result struct {
	Target          kube.Target   `json:"target"`
	Mode            string        `json:"mode"`
	ImageRef        string        `json:"imageRef,omitempty"`
	Platform        string        `json:"platform,omitempty"`
	ImagePackages   int           `json:"imagePackages"`
	RuntimePackages int           `json:"runtimePackages"`
	ImageSBOM       string        `json:"imageSBOM,omitempty"`
	RuntimeSBOM     string        `json:"runtimeSBOM,omitempty"`
	Rootfs          *rootfs.Stats `json:"rootfs,omitempty"`
	Drift           *drift.Report `json:"drift,omitempty"`
	// RuntimeUnavailable means the image SBOM is all there is for this container.
	RuntimeUnavailable bool        `json:"runtimeUnavailable,omitempty"`
	Excluded           []Exclusion `json:"excluded,omitempty"`
	// NotCovered lists places the runtime SBOM could not look at, so that
	// "no drift" is never read as "nothing changed anywhere".
	NotCovered []string `json:"notCovered,omitempty"`
	Warnings   []string `json:"warnings,omitempty"`
	Errors     []string `json:"errors,omitempty"`
}

type Scanner struct {
	kube   *kube.Client
	gen    sbomgen.Generator
	opts   Options
	log    io.Writer
	images map[string]*sbom.SBOM
}

func New(k *kube.Client, gen sbomgen.Generator, opts Options, log io.Writer) *Scanner {
	return &Scanner{kube: k, gen: gen, opts: opts, log: log, images: map[string]*sbom.SBOM{}}
}

func (s *Scanner) Scan(ctx context.Context, t kube.Target) Result {
	if s.opts.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.opts.Timeout)
		defer cancel()
	}
	res := Result{Target: t, Mode: s.opts.Mode}
	dir := filepath.Join(s.opts.OutputDir, t.Namespace, t.Pod, t.Container)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		res.Errors = append(res.Errors, err.Error())
		return res
	}

	var imageSBOM, runtimeSBOM *sbom.SBOM

	if !s.opts.SkipImage {
		s.logf("%s: image SBOM", t)
		sb, err := s.imageSBOM(ctx, t, &res)
		err = s.timeoutError(ctx, err)
		if err != nil {
			res.Errors = append(res.Errors, "image: "+err.Error())
		} else {
			imageSBOM = sb
			res.ImagePackages = sb.Artifacts.Packages.PackageCount()
			res.ImageSBOM = filepath.Join(dir, "image.cdx.json")
			if err := sbomgen.WriteCycloneDX(sb, res.ImageSBOM); err != nil {
				res.Errors = append(res.Errors, err.Error())
			}
		}
	}

	if !s.opts.SkipRuntime {
		s.logf("%s: runtime SBOM (copying the filesystem out of the sandbox)", t)
		sb, err := s.runtimeSBOM(ctx, t, dir, imageSBOM, &res)
		err = s.timeoutError(ctx, err)
		if errors.Is(err, ErrNoTar) {
			res.RuntimeUnavailable = true
			res.Warnings = append(res.Warnings, "runtime: "+err.Error())
		} else if err != nil {
			res.Errors = append(res.Errors, "runtime: "+err.Error())
		} else {
			runtimeSBOM = sb
			res.RuntimePackages = sb.Artifacts.Packages.PackageCount()
			res.RuntimeSBOM = filepath.Join(dir, "runtime.cdx.json")
			if err := sbomgen.WriteCycloneDX(sb, res.RuntimeSBOM); err != nil {
				res.Errors = append(res.Errors, err.Error())
			}
		}
	}

	if imageSBOM != nil && runtimeSBOM != nil {
		d := drift.Compare(drift.Packages(imageSBOM), drift.Packages(runtimeSBOM))
		res.Drift = &d
	}

	if b, err := json.MarshalIndent(res, "", "  "); err == nil {
		_ = os.WriteFile(filepath.Join(dir, "result.json"), b, 0o644)
	}
	return res
}

func (s *Scanner) imageSBOM(ctx context.Context, t kube.Target, res *Result) (*sbom.SBOM, error) {
	ref, err := kube.ImageRef(t.Image, t.ImageID)
	if err != nil {
		return nil, err
	}
	res.ImageRef = ref

	platform, err := s.kube.Platform(ctx, t.Node)
	if err != nil {
		res.Warnings = append(res.Warnings, "could not read node platform, using the registry default: "+err.Error())
	}
	res.Platform = platform

	key := ref + "|" + platform
	if sb, ok := s.images[key]; ok {
		return sb, nil
	}
	sb, err := s.gen.FromImage(ctx, ref, platform)
	if err != nil {
		return nil, err
	}
	s.images[key] = sb
	return sb, nil
}

func (s *Scanner) runtimeSBOM(ctx context.Context, t kube.Target, dir string, image *sbom.SBOM, res *Result) (*sbom.SBOM, error) {
	work, err := os.MkdirTemp("", "gvsbom-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(work)
	copyDir := filepath.Join(work, "rootfs")
	if s.opts.KeepRootfs {
		copyDir = filepath.Join(dir, "rootfs")
		if err := os.RemoveAll(copyDir); err != nil {
			return nil, err
		}
	}
	if err := os.Mkdir(copyDir, 0o755); err != nil {
		return nil, err
	}

	if s.opts.Mode == ModeNode {
		return s.fromUpperLayer(ctx, t, work, copyDir, image, res)
	}

	excl, warning := s.planCopy(ctx, t)
	if warning != "" {
		res.Warnings = append(res.Warnings, warning)
	}
	res.Excluded = excl

	st, warning, err := s.copyRootfs(ctx, t, copyDir, excl)
	if warning != "" {
		res.Warnings = append(res.Warnings, warning)
	}
	if err != nil {
		return nil, err
	}
	res.Rootfs = &st
	if st.Skipped > 0 {
		res.Warnings = append(res.Warnings, fmt.Sprintf("%d archive entries skipped (devices, or paths that would leave the copy)", st.Skipped))
	}
	return s.gen.FromRootfs(ctx, copyDir, t.String())
}

// planCopy decides which mounts to leave out, from the container's own mount
// table when it can be read and from the pod spec otherwise.
func (s *Scanner) planCopy(ctx context.Context, t kube.Target) ([]Exclusion, string) {
	out := &limitedBuffer{max: 1 << 20}
	stderr := &limitedBuffer{max: 4096}
	err := s.kube.Exec(ctx, t, []string{"cat", "/proc/self/mountinfo"}, out, stderr)
	mounts := parseMountinfo(out.String())
	if err != nil || len(mounts) == 0 || len(mounts) > maxMounts {
		return planFromSpec(t.Mounts, s.opts.IncludeVolumes),
			"could not read the container's mount table, so mounts were excluded by their pod spec paths"
	}
	return planExclusions(mounts, t.Mounts, s.opts.IncludeVolumes), ""
}

// copyRootfs streams `tar` from inside the sandbox straight into a local
// directory, without buffering the archive.
func (s *Scanner) copyRootfs(ctx context.Context, t kube.Target, dir string, excl []Exclusion) (rootfs.Stats, string, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	pr, pw := io.Pipe()
	stderr := &limitedBuffer{max: 4096}
	execDone := make(chan error, 1)
	go func() {
		err := s.kube.Exec(ctx, t, tarArgs(excl), pw, stderr)
		pw.CloseWithError(err)
		execDone <- err
	}()

	st, xerr := rootfs.Extract(pr, dir, rootfs.Limits{
		MaxBytes:   s.opts.MaxRootfsBytes,
		MaxEntries: s.opts.MaxEntries,
		Exclude:    extractExcludes(excl),
	})
	if xerr == nil {
		_, _ = io.Copy(io.Discard, pr)
	} else {
		cancel()
		pr.CloseWithError(xerr)
	}
	execErr := <-execDone

	if errors.Is(xerr, rootfs.ErrTooLarge) || errors.Is(xerr, rootfs.ErrTooManyEntries) {
		return st, "", s.limitError(xerr)
	}
	if execErr != nil {
		warning, err := classifyExecError(execErr, stderr.String())
		if err != nil {
			return st, "", err
		}
		return st, warning, xerr
	}
	return st, "", xerr
}

func classifyExecError(err error, stderr string) (string, error) {
	msg := err.Error() + " " + stderr
	for _, s := range []string{
		"executable file not found",      // runc
		`error finding executable "tar"`, // gVisor
		`"tar": no such file`,
	} {
		if strings.Contains(msg, s) {
			return "", ErrNoTar
		}
	}
	var exitErr utilexec.ExitError
	if errors.As(err, &exitErr) {
		switch exitErr.ExitStatus() {
		case 1:
			// GNU tar: some files changed while being read. The archive is still complete.
			return "tar: files changed while being copied: " + clean.Message(firstLine(stderr)), nil
		case 126, 127:
			return "", ErrNoTar
		}
	}
	return "", fmt.Errorf("tar inside the container failed: %w: %s", err, clean.Message(strings.TrimSpace(stderr)))
}

// fromUpperLayer builds the runtime SBOM in node mode: gVisor serialises what
// changed in the container's root filesystem, and that is merged into the
// image SBOM. Nothing runs inside the workload.
func (s *Scanner) fromUpperLayer(ctx context.Context, t kube.Target, work, copyDir string, image *sbom.SBOM, res *Result) (*sbom.SBOM, error) {
	if image == nil {
		return nil, errors.New("node mode merges runtime changes into the image SBOM, which could not be built")
	}
	id, err := runsc.ContainerID(t.ContainerID)
	if err != nil {
		return nil, err
	}
	archive := filepath.Join(work, "upper.tar")
	if err := s.opts.Runsc.RootfsUpper(ctx, id, archive); err != nil {
		return nil, err
	}
	f, err := os.Open(archive)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if fi, err := f.Stat(); err == nil && fi.Size() > s.opts.MaxRootfsBytes {
		return nil, s.limitError(rootfs.ErrTooLarge)
	}

	st, err := rootfs.Extract(f, copyDir, rootfs.Limits{MaxBytes: s.opts.MaxRootfsBytes, MaxEntries: s.opts.MaxEntries})
	if err != nil {
		return nil, s.limitError(err)
	}
	res.Rootfs = &st
	res.NotCovered = notCoveredInNodeMode(t.Mounts)

	upper, err := s.gen.FromRootfs(ctx, copyDir, t.String())
	if err != nil {
		return nil, err
	}
	return overlay.Merge(image, upper, overlay.Changes{Dir: copyDir, Whiteouts: st.Whiteouts, Opaque: st.Opaque})
}

// notCoveredInNodeMode lists what lives outside the root filesystem's upper
// layer: gVisor's in-memory /tmp, and every volume that is not a credential
// volume (those are never scanned in any mode).
func notCoveredInNodeMode(mounts []kube.VolumeMount) []string {
	out := []string{"/tmp (gVisor keeps it in memory)"}
	for _, m := range mounts {
		if !m.Sensitive() {
			out = append(out, fmt.Sprintf("%s (%s volume)", m.Path, m.Kind))
		}
	}
	return out
}

func (s *Scanner) limitError(err error) error {
	switch {
	case errors.Is(err, rootfs.ErrTooLarge):
		return fmt.Errorf("%w (limit %d MiB, see --max-rootfs-mb)", err, s.opts.MaxRootfsBytes>>20)
	case errors.Is(err, rootfs.ErrTooManyEntries):
		return fmt.Errorf("%w (limit %d, see --max-entries)", err, s.opts.MaxEntries)
	}
	return err
}

func (s *Scanner) timeoutError(ctx context.Context, err error) error {
	if err != nil && errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return fmt.Errorf("scan timed out after %s (see --timeout)", s.opts.Timeout)
	}
	return err
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func (s *Scanner) logf(format string, args ...any) {
	if s.log != nil {
		fmt.Fprintf(s.log, format+"\n", args...)
	}
}

type limitedBuffer struct {
	bytes.Buffer
	max int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if room := b.max - b.Len(); room > 0 {
		if len(p) > room {
			b.Buffer.Write(p[:room])
		} else {
			b.Buffer.Write(p)
		}
	}
	return len(p), nil
}
