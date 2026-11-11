.PHONY: clean build test

build:
	pnpm --dir ui install --frozen-lockfile
	pnpm --dir ui build
	cp ui/embed_dist.snippet ui/embed_dist.go
	CGO_ENABLED=0 go build -o vibecollector ./cmd/vibecollector; status=$$?; rm -f ui/embed_dist.go; \
		test $$status -eq 0 && CGO_ENABLED=0 go build -o vibecollector-clients ./cmd/vibecollector-clients && \
		CGO_ENABLED=0 go build -o vibecollector-config ./cmd/vibecollector-config; \
		exit $$?

test:
	CGO_ENABLED=0 go test ./...

clean-ui:
	pnpm --dir ui clean

clean-bins:
	rm -fv vibecollector vibecollector-clients vibecollector-config

clean: clean-ui clean-bins
	@echo cleaned
