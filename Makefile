VERSION_OUTPUT := pathproof dev

.PHONY: fmt test test-race lint test-integration build check

fmt:
	go fmt ./...

test:
	go test ./...

test-race:
	go test -race ./...

lint:
	go vet ./...

test-integration:
	@test "$$(go run ./cmd/pathproof version)" = "$(VERSION_OUTPUT)"

build:
	go build -o bin/pathproof ./cmd/pathproof

check: fmt test test-race lint test-integration build
