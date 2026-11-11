.PHONY: clean compile test

PREFIX  ?= /usr/local
BINDIR  ?= $(PREFIX)/bin
DESTDIR ?=

_OUT ?= out
_BINS := $(_OUT)/vibecollector out/vibecollector-manage out/vibecollector-genconf

_UI_ASSET := ui/embed_dist.go

build: compile

compile-ui: $(_UI_ASSET)

$(_UI_ASSET):
	pnpm --dir ui install --frozen-lockfile
	pnpm --dir ui build
	cp -av ui/embed_dist.snippet $(_UI_ASSET)
	@echo compiled ui

$(_OUT):
	mkdir -vp $(_OUT)

$(_OUT)/vibecollector: $(_OUT) $(_UI_ASSET)
	CGO_ENABLED=0 go build -o $(_OUT)/vibecollector ./cmd/vibecollector

$(_OUT)/vibecollector-manage: $(_OUT)
	CGO_ENABLED=0 go build -o $(_OUT)/vibecollector-manage ./cmd/manage

$(_OUT)/vibecollector-genconf: $(_OUT)
	CGO_ENABLED=0 go build -o $(_OUT)/vibecollector-genconf ./cmd/genconf

compile-bins: $(_BINS)
	@echo compiled bins

compile: compile-ui compile-bins
	@echo compiled


test:
	CGO_ENABLED=0 go test ./...

clean-ui:
	pnpm --dir ui clean
	rm -fv ui/embed_dist.go

clean-bins:
	rm -rfv $(_OUT)

clean: clean-ui clean-bins clean-package
	@echo cleaned

install:
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 $(_OUT)/vibecollector $(DESTDIR)$(BINDIR)/vibecollector
	install -m 755 $(_OUT)/vibecollector-manage $(DESTDIR)$(BINDIR)/vibecollector-manage
	install -m 755 $(_OUT)/vibecollector-genconf $(DESTDIR)$(BINDIR)/vibecollector-genconf

clean-package:
	rm -rfv dist

package: compile
	mkdir -vp dist
	nfpm pkg --packager deb --target dist
	nfpm pkg --packager rpm --target dist
