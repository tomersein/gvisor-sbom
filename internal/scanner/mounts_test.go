package scanner

import (
	"reflect"
	"testing"

	"github.com/tomersein/gvisor-sbom/internal/kube"
)

// Captured from a python:3.12-slim pod running under gVisor (runsc
// release-20260928.0), plus a secret volume, a data volume and a path with a space.
const gvisorMountinfo = `36 35 0:36 / / rw - overlay none rw
38 36 0:37 / /dev rw,nosuid - dev none rw,mode=0755
39 36 0:38 / /sys ro,nosuid,noexec - sysfs none ro,dentry_cache_limit=1000
40 36 0:39 / /proc rw,nosuid,noexec - proc none rw,dentry_cache_limit=1000
41 38 0:22 / /dev/pts rw,nosuid,noexec - devpts none rw
43 36 0:40 / /etc/hosts rw - 9p none rw,trans=fd,rfdno=50,wfdno=50,aname=/
45 39 0:43 / /sys/fs/cgroup ro,nosuid,noexec - tmpfs none ro
55 36 0:46 / /run/secrets/kubernetes.io/serviceaccount ro - 9p none ro,trans=fd,rfdno=54,wfdno=54,aname=/
56 36 0:47 / /tmp rw - tmpfs none rw,mode=01777
57 36 0:48 / /etc/creds ro - tmpfs none ro
58 36 0:49 / /opt/venv rw - 9p none rw,trans=fd
59 36 0:50 / /srv/my\040data rw - 9p none rw,trans=fd
`

var spec = []kube.VolumeMount{
	{Path: "/var/run/secrets/kubernetes.io/serviceaccount", Volume: "kube-api-access", Kind: "projected"},
	{Path: "/etc/creds", Volume: "creds", Kind: "secret"},
	{Path: "/opt/venv", Volume: "venv", Kind: "emptyDir"},
	{Path: "/srv/my data", Volume: "data", Kind: "persistentVolumeClaim"},
}

func TestPlanExclusions(t *testing.T) {
	got := planExclusions(parseMountinfo(gvisorMountinfo), spec, false)
	want := []Exclusion{
		{"/dev", reasonKernel},
		{"/etc/creds", reasonSecret},
		{"/etc/hosts", reasonVolume},
		{"/opt/venv", reasonVolume},
		{"/proc", reasonKernel},
		{"/run/secrets/kubernetes.io/serviceaccount", reasonSecret},
		{"/srv/my data", reasonVolume},
		{"/sys", reasonKernel},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got  %v\nwant %v", got, want)
	}
}

func TestPlanExclusionsIncludeVolumesKeepsSecretsOut(t *testing.T) {
	got := planExclusions(parseMountinfo(gvisorMountinfo), spec, true)
	want := []Exclusion{
		{"/dev", reasonKernel},
		{"/etc/creds", reasonSecret},
		{"/proc", reasonKernel},
		{"/run/secrets/kubernetes.io/serviceaccount", reasonSecret},
		{"/sys", reasonKernel},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got  %v\nwant %v", got, want)
	}
}

func TestPlanFromSpecCoversVarRunAlias(t *testing.T) {
	got := planFromSpec(spec, true)
	want := []Exclusion{
		{"/dev", reasonKernel},
		{"/etc/creds", reasonSecret},
		{"/proc", reasonKernel},
		{"/run/secrets/kubernetes.io/serviceaccount", reasonSecret},
		{"/sys", reasonKernel},
		{"/var/run/secrets/kubernetes.io/serviceaccount", reasonSecret},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got  %v\nwant %v", got, want)
	}
}

func TestTarArgs(t *testing.T) {
	got := tarArgs([]Exclusion{{"/proc", reasonKernel}, {"/srv/my data", reasonVolume}})
	want := []string{"tar", "cf", "-", "--exclude=./proc", "--exclude=./srv/my data", "-C", "/", "."}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q", got)
	}
}

func TestParseMountinfoDropsUntrustedPaths(t *testing.T) {
	got := parseMountinfo(`36 35 0:36 / / rw - overlay none rw
60 36 0:51 / relative/path rw - 9p none rw
61 36 0:52 / /a/../etc rw - 9p none rw
62 36 0:53 / /evil\033[2K rw - 9p none rw
63 36 0:54 / /ok rw - 9p none rw
`)
	want := []procMount{{"/", "overlay"}, {"/ok", "9p"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}
