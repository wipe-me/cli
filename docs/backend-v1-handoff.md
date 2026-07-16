# Backend v1 integration status

Status: implemented. This file is retained as an integration pointer, not a plan.

The central contract lives in the web/backend workspace:

- `docs/backend-architecture.md`
- `docs/decisions/0001-api-v1.md`
- `openapi/wipe-api.v1.yaml`

The cryptographic contract and cross-language fixtures live in the public
[Wipe.me SDK](https://github.com/wipe-me/sdk), under `specification/` and
`fixtures/v1/`. The CLI consumes its versioned Go package instead of maintaining
its own protocol or HTTP client implementation.

## Current behavior

- IDs are 12 Base58BTC characters; 16-character secrets remain in URL fragments.
- CLI, web, and SDK clients use unified encrypted envelope v1.
- Every v1 message is one-time. `X-Wipe-On-Read` is unsupported and is not sent.
- `X-Wipe-Client` is optional extensible metadata and never affects cryptography.
- Free anonymous messages are limited to 3 MiB encrypted and 14 days.
- Retrieval is an atomic claim. The winner retains the already-open R2 stream after
  the object and active D1 row are removed.
- A per-message Durable Object stores the retirement marker that prevents concurrent
  claims and reuse of claimed, deleted, or expired IDs.
- Manual deletion uses the locally derived capability; only its verifier is stored.

Contract changes start with a central decision record and OpenAPI update, followed by
shared fixtures and synchronized client implementations.
