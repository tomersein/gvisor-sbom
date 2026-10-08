// Package sbomgen builds SBOMs with syft used as a library.
package sbomgen

import (
	"context"
	"fmt"
	"os"

	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/cataloging"
	"github.com/anchore/syft/syft/cataloging/pkgcataloging"
	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/format/cyclonedxjson"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
	"github.com/anchore/syft/syft/source/directorysource"

	// syft needs a sqlite driver registered to read newer RPM databases.
	_ "modernc.org/sqlite"
)

type Generator struct {
	Tool    string
	Version string
}

// FromImage builds the SBOM of what was shipped: the image the pod runs,
// pulled from its registry by digest.
func (g Generator) FromImage(ctx context.Context, ref, platform string) (*sbom.SBOM, error) {
	cfg := syft.DefaultGetSourceConfig().WithSources("registry")
	if platform != "" {
		p, err := image.NewPlatform(platform)
		if err != nil {
			return nil, err
		}
		cfg = cfg.WithPlatform(p)
	}
	src, err := syft.GetSource(ctx, ref, cfg)
	if err != nil {
		return nil, fmt.Errorf("opening image %s: %w", ref, err)
	}
	defer src.Close()
	return syft.CreateSBOM(ctx, src, g.config())
}

// FromRootfs builds the SBOM of what is running: a container filesystem
// copied out of the sandbox. Base pins symlink resolution to the copy, and the
// image catalogers are used so the result is comparable with FromImage.
func (g Generator) FromRootfs(ctx context.Context, dir, name string) (*sbom.SBOM, error) {
	src, err := directorysource.New(directorysource.Config{
		Path:  dir,
		Base:  dir,
		Alias: source.Alias{Name: name},
	})
	if err != nil {
		return nil, err
	}
	defer src.Close()
	return syft.CreateSBOM(ctx, src, g.config())
}

func (g Generator) config() *syft.CreateSBOMConfig {
	return syft.DefaultCreateSBOMConfig().
		WithTool(g.Tool, g.Version).
		WithCatalogerSelection(cataloging.NewSelectionRequest().WithDefaults(pkgcataloging.ImageTag))
}

func WriteCycloneDX(s *sbom.SBOM, path string) error {
	cfg := cyclonedxjson.DefaultEncoderConfig()
	cfg.Pretty = true
	enc, err := cyclonedxjson.NewFormatEncoderWithConfig(cfg)
	if err != nil {
		return err
	}
	b, err := format.Encode(*s, enc)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}
