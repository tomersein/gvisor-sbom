// Package overlay rebuilds the SBOM of a running container from the SBOM of
// its image and the SBOM of what changed since it started (the overlay upper
// layer).
package overlay

import (
	"os"
	"path"
	"strings"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
)

// Changes describes an extracted upper layer.
type Changes struct {
	Dir       string
	Whiteouts []string
	Opaque    []string
}

// Merge keeps every image package whose evidence is untouched by the upper
// layer, and adds every package found in the upper layer. A package whose
// evidence file was rewritten (dpkg's status after apt install) is dropped
// from the image side and found again, as it is now, on the upper side; one
// whose evidence was deleted (pip uninstall) is dropped.
func Merge(image, upper *sbom.SBOM, ch Changes) (*sbom.SBOM, error) {
	root, err := os.OpenRoot(ch.Dir)
	if err != nil {
		return nil, err
	}
	defer root.Close()

	touched := func(p string) bool {
		rel := strings.TrimPrefix(path.Clean("/"+p), "/")
		for _, w := range ch.Whiteouts {
			if rel == w || strings.HasPrefix(rel, w+"/") {
				return true
			}
		}
		for _, o := range ch.Opaque {
			if strings.HasPrefix(rel, o+"/") {
				return true
			}
		}
		_, err := root.Lstat(rel)
		return err == nil
	}

	var pkgs []pkg.Package
	for _, p := range image.Artifacts.Packages.Sorted() {
		if !evidenceTouched(p, touched) {
			pkgs = append(pkgs, p)
		}
	}
	pkgs = append(pkgs, upper.Artifacts.Packages.Sorted()...)
	merged := pkg.NewCollection(pkgs...)

	distro := upper.Artifacts.LinuxDistribution
	if distro == nil {
		distro = image.Artifacts.LinuxDistribution
	}

	return &sbom.SBOM{
		Artifacts: sbom.Artifacts{
			Packages:          merged,
			LinuxDistribution: distro,
		},
		Relationships: packageRelationships(merged, image.Relationships, upper.Relationships),
		Source:        upper.Source,
		Descriptor:    upper.Descriptor,
	}, nil
}

// evidenceTouched looks at a package's primary evidence (the file it was
// identified from), falling back to all its locations when none is marked.
func evidenceTouched(p pkg.Package, touched func(string) bool) bool {
	locs := p.Locations.ToSlice()
	var primary []file.Location
	for _, l := range locs {
		if l.Annotations[pkg.EvidenceAnnotationKey] == pkg.PrimaryEvidenceAnnotation {
			primary = append(primary, l)
		}
	}
	if len(primary) == 0 {
		primary = locs
	}
	for _, l := range primary {
		if touched(l.RealPath) {
			return true
		}
	}
	return false
}

// packageRelationships keeps relationships between packages that are both
// still present. File-level relationships are not carried over.
func packageRelationships(c *pkg.Collection, sets ...[]artifact.Relationship) []artifact.Relationship {
	var out []artifact.Relationship
	for _, rels := range sets {
		for _, r := range rels {
			from, fromPkg := r.From.(pkg.Package)
			to, toPkg := r.To.(pkg.Package)
			if fromPkg && toPkg && c.Package(from.ID()) != nil && c.Package(to.ID()) != nil {
				out = append(out, r)
			}
		}
	}
	return out
}
