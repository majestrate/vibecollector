package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestDocumentRoundTrip(t *testing.T) {
	def, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	doc, err := Document(def)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(doc, "listen = '127.0.0.1:8080'") || !strings.Contains(doc, "listen = '0.0.0.0:2055'") {
		t.Fatal(doc)
	}
	if !strings.Contains(doc, "public_host = ''") || !strings.Contains(doc, "token = ''") {
		t.Fatal(doc)
	}
	if !strings.Contains(doc, "template_idle_timeout = '30m'") || !strings.Contains(doc, "batch_interval = '500ms'") {
		t.Fatal(doc)
	}
	if strings.Contains(doc, "[enrich.geoip]") || strings.Contains(doc, "client_secret") {
		t.Fatal(doc)
	}
	path := filepath.Join(t.TempDir(), "vibecollector.toml")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(Flags{ConfigPath: path})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(cfg, def) {
		t.Fatalf("loaded %#v\ndefault %#v", cfg, def)
	}
	again, err := Document(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if again != doc {
		t.Fatal("document is not stable")
	}
	nilDoc, err := Document(nil)
	if err != nil || nilDoc != "" {
		t.Fatal("nil document", err, nilDoc)
	}
}
