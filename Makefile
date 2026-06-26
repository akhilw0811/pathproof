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
	@tmp="$$(mktemp -d)"; \
	go build -o "$$tmp/pathproof" ./cmd/pathproof; \
	test "$$("$$tmp/pathproof" version)" = "$(VERSION_OUTPUT)"; \
	"$$tmp/pathproof" scan ./cmd/pathproof/testdata/scan-safe >/dev/null; \
	code=0; "$$tmp/pathproof" scan ./cmd/pathproof/testdata/scan-vulnerable >/dev/null || code=$$?; test "$$code" = "1"; \
	code=0; "$$tmp/pathproof" scan ./cmd/pathproof/testdata/scan-invalid >/dev/null 2>/dev/null || code=$$?; test "$$code" = "2"

build:
	go build -o bin/pathproof ./cmd/pathproof

check: fmt test test-race lint test-integration build
