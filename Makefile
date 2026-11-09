.PHONY: build test

build:
	CGO_ENABLED=0 go build -o vibecollector ./cmd/vibecollector

test:
	CGO_ENABLED=0 go test ./...
