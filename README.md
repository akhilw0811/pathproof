# PathProof

PathProof is a defensive, cloud-agnostic attack-path verification engine.

It ingests infrastructure and software-supply-chain artifacts, models security
relationships as an evidence-backed graph, detects attack paths, generates
minimal remediation patches, and proves through rescanning that paths were
broken.

## Current milestone

Build a tested Go CLI bootstrap. Graph domain logic is not implemented yet.

## Usage

```sh
go run ./cmd/pathproof version
```

Expected output:

```text
pathproof dev
```

## Development

```sh
make check
make build
```

The built binary is written to `bin/pathproof`.

## Not currently in scope

- Kubernetes parsing
- Terraform parsing
- GitHub Actions parsing
- SBOM parsing
- AI agents
- Machine learning
- Dashboard
- Graph database
- GitHub pull request creation
