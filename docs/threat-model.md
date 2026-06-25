# Threat Model

PathProof is defensive software for verifying security claims from graph or
source evidence.

Current bootstrap assumptions:

- The CLI accepts only local command-line input.
- No credentials, tokens, secrets, or personal data are required.
- No exploit execution, credential theft, persistence, destructive action, or
  unauthorized access is in scope.
- Future AI output must be treated as untrusted input.

Fixtures and tests must not contain real secrets or personal data.
