# PathProof Instructions

## Mission

PathProof is a defensive, cloud-agnostic attack-path verification engine.
Security claims must be backed by deterministic graph or source evidence.

## Current milestone

Build only the smallest functionality needed for the current task.
Do not implement future roadmap features unless explicitly requested.

## Non-negotiable rules

- Do not overengineer.
- Prefer the simplest complete implementation.
- Do not add speculative abstractions.
- Do not add an interface unless multiple implementations exist now or testing
  clearly requires one.
- Do not add a dependency unless the standard library is insufficient.
- Explain and justify every new dependency before adding it.
- Do not implement exploit execution, credential theft, destructive actions,
  persistence, or unauthorized access.
- Never place real credentials, tokens, secrets, or personal data in fixtures.
- Do not change unrelated files.
- Do not commit, push, or rewrite Git history unless explicitly instructed.

## Architecture rules

- Keep the graph in memory initially.
- Use explicit Go types for security-critical data.
- Use stable deterministic identifiers.
- Preserve evidence for graph relationships.
- Keep parsing, graph storage, analysis, verification, and remediation separate.
- Deterministic code decides whether a path exists or was remediated.
- AI output will eventually be treated as untrusted input.

## Required development workflow

Before editing:

1. Read relevant code, tests, and documentation.
2. State the smallest implementation plan.
3. Identify exactly which files should change.
4. Identify the tests that will prove the implementation.

During implementation:

1. Make one focused change at a time.
2. Add tests alongside the implementation.
3. Run the narrowest relevant test after every meaningful change.
4. Fix all failures before expanding the implementation.
5. Never remove, skip, or weaken a test merely to make it pass.

Before reporting completion:

1. Run formatting.
2. Run tests for changed packages.
3. Run the complete unit test suite.
4. Run integration tests relevant to the change.
5. Run static analysis.
6. Run race tests when applicable.
7. Inspect the complete Git diff.
8. Review for correctness, security, unnecessary complexity, and missing
   negative tests.
9. Report every validation command and whether it passed.

## Standard commands

Once the repository bootstrap exists, use:

- `make fmt`
- `make test`
- `make test-race`
- `make lint`
- `make test-integration`
- `make check`

## Definition of done

A task is complete only when:

- The requested behavior works.
- Positive and negative tests exist.
- Relevant validation commands pass.
- Output is deterministic where required.
- Errors are actionable.
- No unrelated files changed.
- No unexplained TODO placeholders remain.
- No deferred feature was implemented accidentally.
