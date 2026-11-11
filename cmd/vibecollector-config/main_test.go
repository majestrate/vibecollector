package main

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"vibecollector/internal/config"
)

func TestPrintsDefaults(t *testing.T) {
	var out, errb bytes.Buffer
	if code := execute(nil, &out, &errb); code != 0 {
		t.Fatal(code, errb.String())
	}
	if errb.Len() != 0 {
		t.Fatal(errb.String())
	}
	if !strings.Contains(out.String(), "api_prefix = '/api/v1'\n") {
		t.Fatal(out.String())
	}
	path := filepath.Join(t.TempDir(), "vibecollector.toml")
	if err := os.WriteFile(path, out.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := config.Load(config.Flags{ConfigPath: path})
	if err != nil {
		t.Fatal(err)
	}
	want, err := config.Default()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v\nwant %#v", got, want)
	}
}

func TestRejectsArgs(t *testing.T) {
	var out, errb bytes.Buffer
	if code := execute([]string{"-h"}, &out, &errb); code != 2 {
		t.Fatal(code, out.String(), errb.String())
	}
	if out.Len() != 0 || !strings.Contains(errb.String(), "usage:") {
		t.Fatal(out.String(), errb.String())
	}
}
