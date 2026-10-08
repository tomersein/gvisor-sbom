// Package drift compares the packages in an image with those in a running container.
package drift

import (
	"sort"

	"github.com/anchore/syft/syft/sbom"
)

type Package struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Type    string `json:"type"`
	PURL    string `json:"purl,omitempty"`
}

type Change struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	FromVersion string `json:"fromVersion"`
	ToVersion   string `json:"toVersion"`
}

type Report struct {
	Added   []Package `json:"added"`
	Removed []Package `json:"removed"`
	Changed []Change  `json:"changed"`
}

func (r Report) Empty() bool {
	return len(r.Added) == 0 && len(r.Removed) == 0 && len(r.Changed) == 0
}

func Packages(s *sbom.SBOM) []Package {
	var out []Package
	for _, p := range s.Artifacts.Packages.Sorted() {
		out = append(out, Package{Name: p.Name, Version: p.Version, Type: string(p.Type), PURL: p.PURL})
	}
	return out
}

// Compare reports what the running container has that the image does not, and
// the reverse. A package present on both sides with a different version is a
// change rather than an add plus a remove.
func Compare(image, runtime []Package) Report {
	imgSet, rtSet := index(image), index(runtime)
	var added, removed []Package
	for k, p := range rtSet {
		if _, ok := imgSet[k]; !ok {
			added = append(added, p)
		}
	}
	for k, p := range imgSet {
		if _, ok := rtSet[k]; !ok {
			removed = append(removed, p)
		}
	}

	var r Report
	gone := map[string][]Package{}
	for _, p := range removed {
		gone[p.Type+"/"+p.Name] = append(gone[p.Type+"/"+p.Name], p)
	}
	for _, p := range added {
		id := p.Type + "/" + p.Name
		if old := gone[id]; len(old) == 1 {
			r.Changed = append(r.Changed, Change{Name: p.Name, Type: p.Type, FromVersion: old[0].Version, ToVersion: p.Version})
			delete(gone, id)
			continue
		}
		r.Added = append(r.Added, p)
	}
	for _, ps := range gone {
		r.Removed = append(r.Removed, ps...)
	}

	sortPackages(r.Added)
	sortPackages(r.Removed)
	sort.Slice(r.Changed, func(i, j int) bool { return r.Changed[i].Name < r.Changed[j].Name })
	return r
}

func index(ps []Package) map[string]Package {
	m := make(map[string]Package, len(ps))
	for _, p := range ps {
		m[p.Type+"/"+p.Name+"@"+p.Version] = p
	}
	return m
}

func sortPackages(ps []Package) {
	sort.Slice(ps, func(i, j int) bool {
		if ps[i].Name != ps[j].Name {
			return ps[i].Name < ps[j].Name
		}
		return ps[i].Version < ps[j].Version
	})
}
