# Architecture

PathProof is starting as a small Go CLI. The current executable lives at
`cmd/pathproof` and supports only `pathproof version`.

Future security functionality must keep parsing, graph storage, analysis,
verification, and remediation separate. Deterministic code must decide whether
an attack path exists or was remediated.

No graph engine, parsers, AI, dashboard, database, plugin system, or external
service integration is implemented in this bootstrap.
