package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

func TestClientTool(t *testing.T) {
	db := filepath.Join(t.TempDir(), "t.db")
	var out, errb bytes.Buffer
	if code := execute([]string{"add", "-db", db, "-id", "alpha", "-secret", "s3cret"}, &out, &errb); code != 0 {
		t.Fatal(code, errb.String())
	}
	if out.String() != "added alpha\n" {
		t.Fatal(out.String())
	}
	if strings.Contains(out.String()+errb.String(), "s3cret") {
		t.Fatal("secret printed")
	}
	out.Reset()
	if code := execute([]string{"add", "-db", db, "-id", "beta", "-secret", "other"}, &out, &errb); code != 0 {
		t.Fatal(code, errb.String())
	}
	out.Reset()
	if code := execute([]string{"add", "-db", db, "-id", "alpha", "-secret", "rotated"}, &out, &errb); code != 0 {
		t.Fatal(code, errb.String())
	}
	if out.String() != "updated alpha\n" {
		t.Fatal(out.String())
	}
	out.Reset()
	if code := execute([]string{"list", "-db", db}, &out, &errb); code != 0 {
		t.Fatal(code, errb.String())
	}
	if out.String() != "alpha\nbeta\n" {
		t.Fatal(out.String())
	}
	if strings.Contains(out.String(), "rotated") || strings.Contains(out.String(), "other") {
		t.Fatal(out.String())
	}
	out.Reset()
	if code := execute([]string{"remove", "-db", db, "-id", "beta"}, &out, &errb); code != 0 {
		t.Fatal(code, errb.String())
	}
	out.Reset()
	errb.Reset()
	if code := execute([]string{"remove", "-db", db, "-id", "beta"}, &out, &errb); code != 1 {
		t.Fatal(code, errb.String())
	}
	if code := execute([]string{"add", "-db", db, "-id", "bad id", "-secret", "x"}, &bytes.Buffer{}, &errb); code != 2 {
		t.Fatal(code)
	}
	if code := execute([]string{"list", "-db", db, "-secret", "x"}, &bytes.Buffer{}, &errb); code != 2 {
		t.Fatal(code)
	}
}
