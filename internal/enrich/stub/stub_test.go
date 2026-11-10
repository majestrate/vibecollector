package stub

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"
	"vibecollector/internal/enrich"
	"vibecollector/internal/flow"
)

func TestStubNotConfigured(t *testing.T) {
	for _, name := range []enrich.ProviderName{enrich.ProviderGeoIP, enrich.ProviderASN, enrich.ProviderReputation} {
		p, err := New(name)
		if err != nil {
			t.Fatal(err)
		}
		if p.Name() != name {
			t.Fatal(p.Name())
		}
		got := p.Lookup(context.Background(), netip.MustParseAddr("8.8.8.8"))
		if got.Provider != name || got.Kind != flow.OutcomeNotConfigured || got.ErrCode != "" || got.Geo != nil || got.ASN != nil || got.Rep != nil {
			t.Fatalf("%+v", got)
		}
	}
	if _, err := New("maxmind"); !errors.Is(err, ErrUnknownProvider) {
		t.Fatal(err)
	}
	if _, err := New(""); !errors.Is(err, ErrUnknownProvider) {
		t.Fatal(err)
	}
}

func TestImportGraph(t *testing.T) {
	root := moduleRoot(t)
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedImports,
		Dir:  root,
	}
	pkgs, err := packages.Load(cfg, "vibecollector/internal/enrich/stub", "vibecollector/internal/enrich")
	if err != nil {
		t.Fatal(err)
	}
	var stubPkg, enrichPkg *packages.Package
	for _, p := range pkgs {
		for _, e := range p.Errors {
			t.Errorf("%s: %v", p.PkgPath, e)
		}
		switch p.PkgPath {
		case "vibecollector/internal/enrich/stub":
			stubPkg = p
		case "vibecollector/internal/enrich":
			enrichPkg = p
		}
	}
	if stubPkg == nil || enrichPkg == nil {
		t.Fatalf("loaded %#v", pkgs)
	}
	allowed := map[string]bool{
		"context":                       true,
		"net/netip":                     true,
		"vibecollector/internal/enrich": true,
	}
	if len(stubPkg.Imports) != len(allowed) {
		var paths []string
		for path := range stubPkg.Imports {
			paths = append(paths, path)
		}
		t.Fatalf("stub imports %v", paths)
	}
	for path := range stubPkg.Imports {
		if bannedImport(path) || !allowed[path] {
			t.Errorf("stub imports %s", path)
		}
	}
	for path := range allowed {
		if _, ok := stubPkg.Imports[path]; !ok {
			t.Errorf("stub missing %s", path)
		}
	}
	for path := range enrichPkg.Imports {
		if path == "vibecollector/internal/enrich/stub" {
			t.Errorf("enrich imports stub")
		}
	}
}

// bannedImport rejects exact paths. A "net" prefix would also reject net/netip.
func bannedImport(path string) bool {
	switch path {
	case "net", "net/http", "os":
		return true
	default:
		return strings.HasPrefix(path, "crypto/")
	}
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}
