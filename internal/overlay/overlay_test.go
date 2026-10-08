package overlay

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
)

func p(name, version string, typ pkg.Type, evidence string) pkg.Package {
	loc := file.NewLocation(evidence).WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation)
	out := pkg.Package{Name: name, Version: version, Type: typ, Locations: file.NewLocationSet(loc)}
	out.SetID()
	return out
}

func doc(pkgs ...pkg.Package) *sbom.SBOM {
	return &sbom.SBOM{Artifacts: sbom.Artifacts{Packages: pkg.NewCollection(pkgs...)}}
}

func names(s *sbom.SBOM) []string {
	var out []string
	for _, p := range s.Artifacts.Packages.Sorted() {
		out = append(out, p.Name+"@"+p.Version)
	}
	sort.Strings(out)
	return out
}

func TestMerge(t *testing.T) {
	const status = "/var/lib/dpkg/status"
	image := doc(
		p("bash", "5.2", pkg.DebPkg, status),
		p("curl", "8.0", pkg.DebPkg, status),
		p("pip", "25.0", pkg.PythonPkg, "/usr/lib/python3/site-packages/pip-25.0.dist-info/METADATA"),
		p("six", "1.16", pkg.PythonPkg, "/usr/lib/python3/site-packages/six-1.16.dist-info/METADATA"),
		p("legacy", "1.0", pkg.PythonPkg, "/opt/app/legacy-1.0.dist-info/METADATA"),
	)
	// The container ran: apt-get remove curl (rewrites dpkg status),
	// pip uninstall six, pip install requests, and replaced /opt/app wholesale.
	upper := doc(
		p("bash", "5.2", pkg.DebPkg, status),
		p("requests", "2.34.2", pkg.PythonPkg, "/usr/lib/python3/site-packages/requests-2.34.2.dist-info/METADATA"),
	)
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "var/lib/dpkg"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "var/lib/dpkg/status"), nil, 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := Merge(image, upper, Changes{
		Dir:       dir,
		Whiteouts: []string{"usr/lib/python3/site-packages/six-1.16.dist-info"},
		Opaque:    []string{"opt/app"},
	})
	if err != nil {
		t.Fatal(err)
	}

	want := []string{"bash@5.2", "pip@25.0", "requests@2.34.2"}
	if g := names(got); !equal(g, want) {
		t.Fatalf("got %v, want %v", g, want)
	}
}

func TestMergeUntouchedImage(t *testing.T) {
	image := doc(p("bash", "5.2", pkg.DebPkg, "/var/lib/dpkg/status"))
	got, err := Merge(image, doc(), Changes{Dir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if g := names(got); !equal(g, []string{"bash@5.2"}) {
		t.Fatalf("got %v", g)
	}
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
