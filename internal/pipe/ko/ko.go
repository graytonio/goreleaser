package ko

import (
	"context"
	"fmt"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/ko/pkg/build"
	"github.com/google/ko/pkg/commands/options"
	"github.com/google/ko/pkg/publish"
	"github.com/goreleaser/goreleaser/internal/ids"
	"github.com/goreleaser/goreleaser/internal/semerrgroup"
	"github.com/goreleaser/goreleaser/internal/tmpl"
	"github.com/goreleaser/goreleaser/pkg/config"
	gcontext "github.com/goreleaser/goreleaser/pkg/context"
	"golang.org/x/tools/go/packages"
	"os"
	"path/filepath"
)

// Pipe that catalogs common artifacts as an SBOM.
type Pipe struct{}

func (Pipe) String() string { return "running ko" }
func (Pipe) Skip(ctx *gcontext.Context) bool {
	return ctx.SkipKo || ctx.Config.Ko.ID == ""
}

// Default sets the Pipes defaults.
func (Pipe) Default(ctx *gcontext.Context) error {
	ids := ids.New("kos")
	cfg := &ctx.Config.Ko
	if err := setConfigDefaults(cfg); err != nil {
		return err
	}
	ids.Inc(cfg.ID)
	return ids.Validate()
}

func setConfigDefaults(cfg *config.Ko) error {
	cfg.Push = true

	if cfg.ID == "" {
		cfg.ID = "default"
	}

	if cfg.BaseImage == "" {
		cfg.BaseImage = "cgr.dev/chainguard/static" // TODO: we can discuss on this
	}

	return nil
}

// Run executes the Pipe.
func (Pipe) Run(ctx *gcontext.Context) error {
	g := semerrgroup.New(ctx.Parallelism)
	g.Go(doBuild(ctx))
	return g.Wait()
}

type buildOptions struct {
	ip                   string
	workingDir           string
	dockerRepo           string
	cosignRepo           string
	platforms            []string
	baseImage            string
	tags                 []string
	sbom                 string
	ldflags              []string
	bare                 bool
	preserverImportPaths bool
	baseImportPaths      bool
}

func (o *buildOptions) makeBuilder(ctx context.Context) (*build.Caching, error) {
	bo := []build.Option{
		build.WithConfig(map[string]build.Config{
			o.ip: {
				Ldflags: o.ldflags,
			},
		}),
		build.WithPlatforms(o.platforms...),
		build.WithBaseImages(func(ctx context.Context, s string) (name.Reference, build.Result, error) {
			ref, err := name.ParseReference(o.baseImage)
			if err != nil {
				return nil, nil, err
			}

			desc, err := remote.Get(ref,
				remote.WithAuthFromKeychain(authn.DefaultKeychain))
			if err != nil {
				return nil, nil, err
			}
			if desc.MediaType.IsImage() {
				img, err := desc.Image()
				return ref, img, err
			}
			if desc.MediaType.IsIndex() {
				idx, err := desc.ImageIndex()
				return ref, idx, err
			}
			return nil, nil, fmt.Errorf("unexpected base image media type: %s", desc.MediaType)
		}),
	}
	switch o.sbom {
	case "spdx":
		bo = append(bo, build.WithSPDX("devel"))
	case "cyclonedx":
		bo = append(bo, build.WithCycloneDX())
	case "go.version-m":
		bo = append(bo, build.WithGoVersionSBOM())
	case "none":
		// don't do anything.
	default:
		return nil, fmt.Errorf("unknown sbom type: %q", o.sbom)
	}

	b, err := build.NewGo(ctx, o.workingDir, bo...)
	if err != nil {
		return nil, fmt.Errorf("NewGo: %v", err)
	}
	return build.NewCaching(b)
}

func doBuild(ctx *gcontext.Context) func() error {
	return func() error {
		opts, err := fromConfig(ctx, ctx.Config.Ko)
		if err != nil {
			return err
		}

		b, err := opts.makeBuilder(ctx)
		if err != nil {
			return fmt.Errorf("NewGo: %v", err)
		}
		r, err := b.Build(ctx, opts.ip)
		if err != nil {
			return fmt.Errorf("build: %v", err)
		}

		namer := options.MakeNamer(&options.PublishOptions{
			DockerRepo:          opts.dockerRepo,
			Bare:                opts.bare,
			PreserveImportPaths: opts.preserverImportPaths,
			BaseImportPaths:     opts.baseImportPaths,
		})

		p, err := publish.NewDefault(opts.dockerRepo,
			publish.WithTags(opts.tags),
			publish.WithNamer(namer),
			publish.WithAuthFromKeychain(authn.DefaultKeychain))
		if err != nil {
			return fmt.Errorf("NewDefault: %v", err)
		}
		ref, err := p.Publish(ctx, r, opts.ip)
		if err != nil {
			return fmt.Errorf("publish: %v", err)
		}
		fmt.Println(ref.String())
		return nil
	}
}

func fromConfig(ctx *gcontext.Context, cfg config.Ko) (*buildOptions, error) {
	wd, err := os.Getwd()
	if err != nil {
		return nil, err
	}

	localImportPath := fmt.Sprint(".", string(filepath.Separator), ".")

	dir := filepath.Clean(wd)
	if dir == "." {
		dir = ""
	}

	pkgs, err := packages.Load(&packages.Config{Mode: packages.NeedName, Dir: dir}, localImportPath)
	if err != nil {
		return nil, fmt.Errorf("'builds': %s does not contain a valid local import path (%s) for directory (%s): %w", cfg.ID, localImportPath, wd, err)
	}

	if len(pkgs) != 1 {
		return nil, fmt.Errorf("'builds': %s results in %d local packages, only 1 is expected", cfg.ID, len(pkgs))
	}

	opts := &buildOptions{
		ip:                   pkgs[0].PkgPath,
		workingDir:           wd,
		bare:                 cfg.Bare,
		preserverImportPaths: cfg.PreserveImportPaths,
		baseImportPaths:      cfg.BaseImportPaths,
	}

	if cfg.BaseImage != "" {
		opts.baseImage = cfg.BaseImage
	} else {
		opts.baseImage = "cgr.dev/chainguard/static" // TODO: we can discuss on this
	}

	if cfg.Platforms != nil {
		opts.platforms = cfg.Platforms
	} else {
		opts.platforms = []string{"linux/amd64"}
	}

	if cfg.Tags != nil {
		opts.tags = cfg.Tags
	} else {
		opts.tags = []string{"latest"}
	}

	if cfg.SBOM != "" {
		opts.sbom = cfg.SBOM
	} else {
		opts.sbom = "spdx"
	}

	if ctx.Env["KO_DOCKER_REPO"] != "" {
		opts.dockerRepo = ctx.Env["KO_DOCKER_REPO"]
	} else {
		opts.dockerRepo = cfg.Repository
	}

	if ctx.Env["COSIGN_REPOSITORY"] != "" {
		opts.cosignRepo = ctx.Env["COSIGN_REPOSITORY"]
	} else {
		opts.cosignRepo = cfg.CosignRepository
	}

	var ldflags []string
	if len(cfg.LDFlags) != 0 {
		for _, lf := range cfg.LDFlags {
			tlf, err := tmpl.New(ctx).Apply(lf)
			if err != nil {
				return nil, err
			}
			ldflags = append(ldflags, tlf)
		}

		opts.ldflags = ldflags
	}

	return opts, nil
}
