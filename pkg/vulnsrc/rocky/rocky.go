package rocky

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"path/filepath"
	"strings"

	bolt "go.etcd.io/bbolt"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	ustrings "github.com/aquasecurity/trivy-db/pkg/utils/strings"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

const (
	rockyDir       = "rocky"
	platformFormat = "rocky %s"
)

var (
	targetRepos  = []string{"BaseOS", "AppStream", "extras"}
	targetArches = []string{"x86_64"}
	source       = types.DataSource{
		ID:   vulnerability.Rocky,
		Name: "Rocky Linux updateinfo",
		URL:  "https://download.rockylinux.org/pub/rocky/",
	}
)

type Option func(src *VulnSrc)

func WithCustomPut(put db.CustomPut) Option {
	return func(src *VulnSrc) {
		src.put = put
	}
}

func WithDB(db db.Operation) Option {
	return func(src *VulnSrc) {
		src.dbc = db
	}
}

type VulnSrc struct {
	put db.CustomPut
	dbc db.Operation
}

func NewVulnSrc(opts ...Option) VulnSrc {
	src := VulnSrc{
		put: defaultPut,
		dbc: db.Config{},
	}

	for _, o := range opts {
		o(&src)
	}

	return src
}

func (vs VulnSrc) Name() types.SourceID {
	return source.ID
}

func (vs VulnSrc) Update(dir string) error {
	rootDir := filepath.Join(dir, "vuln-list", rockyDir)
	errata := map[string][]RLSA{}
	err := utils.FileWalk(rootDir, func(r io.Reader, path string) error {
		var erratum RLSA
		if err := json.NewDecoder(r).Decode(&erratum); err != nil {
			return xerrors.Errorf("failed to decode Rocky erratum: %w", err)
		}

		dirs := strings.Split(strings.TrimPrefix(path, rootDir), string(filepath.Separator))[1:]
		if len(dirs) != 5 {
			log.Printf("Invalid path: %s", path)
			return nil
		}

		// vulnerabilities are contained in directories with a minor version(like 8.5)
		majorVer := dirs[0]
		if strings.Count(dirs[0], ".") > 0 {
			majorVer = dirs[0][:strings.Index(dirs[0], ".")]
		}
		repo, arch := dirs[1], dirs[2]
		if !ustrings.InSlice(repo, targetRepos) {
			log.Printf("Unsupported Rocky repo: %s", repo)
			return nil
		}

		if !ustrings.InSlice(arch, targetArches) {
			switch arch {
			case "aarch64":
			default:
				log.Printf("Unsupported Rocky arch: %s", arch)
			}
			return nil
		}

		errata[majorVer] = append(errata[majorVer], erratum)
		return nil
	})
	if err != nil {
		return xerrors.Errorf("error in Rocky walk: %w", err)
	}

	if err = vs.save(errata); err != nil {
		return xerrors.Errorf("error in Rocky save: %w", err)
	}

	return nil
}

func (vs VulnSrc) save(errataVer map[string][]RLSA) error {
	err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		err := vs.commit(tx, errataVer)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return xerrors.Errorf("error in db batch update: %w", err)
	}
	return nil
}

func (vs VulnSrc) commit(tx *bolt.Tx, errataVer map[string][]RLSA) error {
	if err := vs.put(vs.dbc, tx, errataVer); err != nil {
		return xerrors.Errorf("put error: %w", err)
	}
	return nil
}

func defaultPut(dbi interface{}, tx *bolt.Tx, advisory interface{}) error {
	dbc := dbi.(db.Config)
	errataVer, ok := advisory.(map[string][]RLSA)
	if !ok {
		return xerrors.New("unknown type")
	}
	for majorVer, errata := range errataVer {
		platformName := fmt.Sprintf(platformFormat, majorVer)
		if err := dbc.PutDataSource(tx, platformName, source); err != nil {
			return xerrors.Errorf("failed to put data source: %w", err)
		}
		for _, erratum := range errata {
			for _, cveID := range erratum.CveIDs {
				putAdvisoryCount := 0
				for _, pkg := range erratum.Packages {
					// Skip the modular packages until the following bug is fixed.
					// https://forums.rockylinux.org/t/some-errata-missing-in-comparison-with-rhel-and-almalinux/3843/8
					if strings.Contains(pkg.Release, ".module+el") {
						continue
					}

					advisory := types.Advisory{
						FixedVersion: utils.ConstructVersion(pkg.Epoch, pkg.Version, pkg.Release),
					}
					if err := dbc.PutAdvisoryDetail(tx, cveID, pkg.Name, []string{platformName}, advisory); err != nil {
						return xerrors.Errorf("failed to save Rocky advisory: %w", err)
					}

					putAdvisoryCount++
				}

				if putAdvisoryCount > 0 {
					var references []string
					for _, ref := range erratum.References {
						references = append(references, ref.Href)
					}

					vuln := types.VulnerabilityDetail{
						Severity:    generalizeSeverity(erratum.Severity),
						References:  references,
						Title:       erratum.Title,
						Description: erratum.Description,
					}
					if err := dbc.PutVulnerabilityDetail(tx, cveID, source.ID, vuln); err != nil {
						return xerrors.Errorf("failed to save Rocky vulnerability: %w", err)
					}

					if err := dbc.PutVulnerabilityID(tx, cveID); err != nil {
						return xerrors.Errorf("failed to save the vulnerability ID: %w", err)
					}
				}
			}
		}
	}
	return nil
}

func (vs VulnSrc) Get(release, pkgName string) ([]types.Advisory, error) {
	bucket := fmt.Sprintf(platformFormat, release)
	advisories, err := vs.dbc.GetAdvisories(bucket, pkgName)
	if err != nil {
		return nil, xerrors.Errorf("failed to get Rocky advisories: %w", err)
	}
	return advisories, nil
}

func generalizeSeverity(severity string) types.Severity {
	switch strings.ToLower(severity) {
	case "low":
		return types.SeverityLow
	case "moderate":
		return types.SeverityMedium
	case "important":
		return types.SeverityHigh
	case "critical":
		return types.SeverityCritical
	}
	return types.SeverityUnknown
}
