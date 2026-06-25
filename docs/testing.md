# Testing

Run the standard local checks before reporting a completed change:

```sh
make fmt
make test
make test-race
make lint
make test-integration
make check
make build
```

The bootstrap CLI is tested through `cmd/pathproof` unit tests and a minimal
integration check that runs `go run ./cmd/pathproof version`.

Tests must cover positive and negative CLI behavior. Do not skip, remove, or
weaken tests to make a change pass.
