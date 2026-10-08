package scanner

import (
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/tomersein/gvisor-sbom/internal/clean"
	"github.com/tomersein/gvisor-sbom/internal/kube"
)

// maxMounts is far above what a real container has. A longer mount table is
// treated as untrustworthy, and the pod spec is used instead.
const maxMounts = 256

// Exclusion is a path inside the container that is not copied out.
type Exclusion struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

const (
	reasonKernel = "kernel view"
	reasonSecret = "secret or config volume"
	reasonVolume = "volume or host-provided mount"
)

type procMount struct {
	Path   string
	FSType string
}

// parseMountinfo reads /proc/self/mountinfo. Mount points are taken from the
// container's own view, so symlinks in the pod spec's paths (/var/run ->
// /run) are already resolved. The table comes from a binary inside the pod,
// so entries that are not clean absolute paths are dropped.
func parseMountinfo(s string) []procMount {
	var out []procMount
	for _, line := range strings.Split(s, "\n") {
		fields := strings.Fields(line)
		sep := -1
		for i, f := range fields {
			if f == "-" {
				sep = i
				break
			}
		}
		if len(fields) < 5 || sep < 0 || sep+1 >= len(fields) {
			continue
		}
		p := unescape(fields[4])
		if !validPath(p) {
			continue
		}
		out = append(out, procMount{Path: p, FSType: fields[sep+1]})
	}
	return out
}

// planExclusions decides what to leave out of the copy. The root filesystem
// and tmpfs mounts hold what the workload installed or wrote, so they are
// copied. Kernel views and credential volumes never are. Other mounts are
// volumes or files the host provides, and are copied only when asked.
func planExclusions(mounts []procMount, spec []kube.VolumeMount, includeVolumes bool) []Exclusion {
	excl := kernelExclusions()
	kernel := []string{"/proc", "/sys", "/dev"}
	sensitive := sensitivePaths(spec)
	for _, m := range mounts {
		switch {
		case m.Path == "/", underAny(m.Path, kernel):
		case underAny(m.Path, sensitive):
			excl = append(excl, Exclusion{m.Path, reasonSecret})
		case m.FSType == "tmpfs", includeVolumes:
		default:
			excl = append(excl, Exclusion{m.Path, reasonVolume})
		}
	}
	return minimize(excl)
}

// planFromSpec is the fallback when the container cannot show its mount
// table. Paths come from the pod spec, so both spellings of /var/run are
// excluded in case one is a symlink to the other.
func planFromSpec(spec []kube.VolumeMount, includeVolumes bool) []Exclusion {
	excl := kernelExclusions()
	for _, m := range spec {
		reason := reasonVolume
		if m.Sensitive() {
			reason = reasonSecret
		} else if includeVolumes {
			continue
		}
		for _, p := range aliases(m.Path) {
			excl = append(excl, Exclusion{p, reason})
		}
	}
	return minimize(excl)
}

func validPath(p string) bool {
	return len(p) <= 4096 && strings.HasPrefix(p, "/") && path.Clean(p) == p && clean.String(p, 4096) == p
}

func kernelExclusions() []Exclusion {
	return []Exclusion{{"/proc", reasonKernel}, {"/sys", reasonKernel}, {"/dev", reasonKernel}}
}

func sensitivePaths(spec []kube.VolumeMount) []string {
	var out []string
	for _, m := range spec {
		if m.Sensitive() {
			out = append(out, aliases(m.Path)...)
		}
	}
	return out
}

func aliases(p string) []string {
	p = "/" + strings.Trim(p, "/")
	switch {
	case p == "/var/run" || strings.HasPrefix(p, "/var/run/"):
		return []string{p, strings.TrimPrefix(p, "/var")}
	case p == "/run" || strings.HasPrefix(p, "/run/"):
		return []string{p, "/var" + p}
	}
	return []string{p}
}

func underAny(p string, prefixes []string) bool {
	for _, pre := range prefixes {
		if p == pre || strings.HasPrefix(p, pre+"/") {
			return true
		}
	}
	return false
}

// minimize drops exclusions already covered by a parent exclusion.
func minimize(excl []Exclusion) []Exclusion {
	sort.Slice(excl, func(i, j int) bool { return excl[i].Path < excl[j].Path })
	var out []Exclusion
	var kept []string
	for _, e := range excl {
		if underAny(e.Path, kept) {
			continue
		}
		out = append(out, e)
		kept = append(kept, e.Path)
	}
	return out
}

func tarArgs(excl []Exclusion) []string {
	args := []string{"tar", "cf", "-"}
	for _, e := range excl {
		args = append(args, "--exclude=."+e.Path)
	}
	return append(args, "-C", "/", ".")
}

func extractExcludes(excl []Exclusion) []string {
	out := make([]string, len(excl))
	for i, e := range excl {
		out[i] = strings.TrimPrefix(e.Path, "/")
	}
	return out
}

// unescape decodes the octal escapes mountinfo uses for spaces and the like.
func unescape(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
