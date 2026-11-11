.PHONY: clean compile test

PREFIX  ?= /usr/local
BINDIR  ?= $(PREFIX)/bin
DESTDIR ?=



OUTBINS := out/vibecollector out/vibecollector-manage out/vibecollector-genconf

build-ui:
	rm -fv ui/embed_dist.go
	pnpm --dir ui install --frozen-lockfile
	pnpm --dir ui build
	cp ui/embed_dist.snippet ui/embed_dist.go

out:
	mkdir -p out

out/vibecollector: out
	CGO_ENABLED=0 go build -o ./out/vibecollector ./cmd/vibecollector;

out/vibecollector-manage: out
	CGO_ENABLED=0 go build -o ./out/vibecollector-manage ./cmd/vibecollector-clients

out/vibecollector-genconf: out
	CGO_ENABLED=0 go build -o ./out/vibecollector-genconf ./cmd/vibecollector-config

build-bins: $(OUTBINS)
	@echo made bins

compile: build-ui build-bins
	@echo built

test:
	CGO_ENABLED=0 go test ./...

clean-ui:
	pnpm --dir ui clean

clean-bins:
	rm -rfv out

clean: clean-ui clean-bins
	@echo cleaned

install:
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 out/vibecollector $(DESTDIR)$(BINDIR)/vibecollector
	install -m 755 out/vibecollector-manage $(DESTDIR)$(BINDIR)/vibecollector-manage
	install -m 755 out/vibecollector-genconf $(DESTDIR)$(BINDIR)/vibecollector-genconf

