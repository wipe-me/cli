# Backend and browser handoff: unified short-link envelope v1

This document is the implementation contract for the backend task. Browser and CLI messages use one identical v1 key schedule, binary envelope, link format, and deletion model. The existing unreleased browser-only v1 format is replaced rather than supported in parallel.

## Final public link

```text
https://wipe.me/1K7m-Q2xR-8VpC#7YWH-Mfk9-JCB7-P4eG
```

- Canonical message ID: 12 Base58BTC characters, without dashes
- Canonical secret: 16 Base58BTC characters, without dashes
- Dashes are presentation-only and accepted by the web UI
- The API path always uses the canonical undashed message ID
- The fragment secret must never be sent to or logged by the backend

## What the backend stores

Store:

- canonical message ID
- opaque v1 envelope object key and encrypted byte size
- cipher version `1`
- lowercase SHA-256 envelope hash supplied by the client
- deletion-key verifier
- expiry and wipe-on-read policy
- existing quota/creator metadata

Never store:

- 16-character secret
- Argon2id root
- encryption root
- manifest or attachment keys
- decrypted filenames, MIME types, message text, or attachment metadata

The CLI sends a 32-byte deletion capability as unpadded base64url. Prefer storing `SHA-256(decodedDeletionKey)` or a server-keyed HMAC verifier rather than the reusable raw deletion capability. On deletion, decode the header, recompute the verifier, and compare in constant time. A migration can replace or supplement the existing `deletion_key` column.

## Create operation

Implement:

```http
PUT /api/messages/{messageId}
Content-Type: application/octet-stream
Content-Length: <exact envelope size>
X-Wipe-Content-Hash: <64 lowercase hex characters>
X-Wipe-Deletion-Key: <43-character unpadded base64url>
X-Wipe-Cipher-Version: 1
X-Wipe-Client: cli
X-Wipe-Expires-At: <Unix epoch milliseconds>
X-Wipe-On-Read: 1
```

Validate `messageId` with:

```regex
^[1-9A-HJ-NP-Za-km-z]{12}$
```

The set is the Base58BTC alphabet and deliberately excludes `0`, `O`, `I`, and `l`.

Response:

```json
{
  "id": "1K7mQ2xR8VpC",
  "created": true
}
```

Retain existing idempotency behavior:

- Same ID, encrypted size, and content hash: `200`, `created:false`
- Same ID with different size or hash: `409`
- Newly stored message: `201`, `created:true`

The backend may treat the envelope as opaque after enforcing its configured size limit. It does not need to parse attachment frames. `X-Wipe-Client` is optional producer metadata such as `cli` or `web`; it must not select a cipher or change decryption behavior.

## Delete operation

Implement or adapt:

```http
DELETE /api/messages/{messageId}
X-Wipe-Deletion-Key: <43-character unpadded base64url>
```

Behavior:

1. Validate the v1 message ID and deletion-key encoding.
2. Compute and constant-time compare the stored deletion verifier.
3. Delete the object, then its metadata.
4. Return `200 {"deleted":true}` for successful, expired, already deleted, or unknown messages.
5. Return `403` when an existing message receives the wrong deletion capability.

Anyone holding the complete private link can derive this capability. No separate privileged creator token is required.

## Retrieval and lifecycle

Add the retrieval/claim operation to OpenAPI only when concurrency semantics are implemented and tested. Required policy:

- `wipe_on_read=1`: atomically grant the first retrieval and prevent a second claim
- `manual`: anyone with the complete link can call the deletion endpoint
- `expires_at`: scheduled cleanup deletes both object and metadata after expiry

The claim must be atomic across concurrent requests. Decide and document whether object deletion occurs immediately after a successful claim or after the response body has been handed to the client. Avoid a flow where an invalid secret can consume a newly reused ID; message IDs must not be deliberately recycled.

## Browser recipient support

The link is useful only after the web application can open it. Update or coordinate the web client to:

1. Route `/<grouped-message-id>` to the recipient view without sending the fragment.
2. Remove dashes and validate the 12-character Base58 ID and 16-character Base58 secret.
3. Claim/download the opaque v1 envelope from the retrieval endpoint.
4. Derive the Argon2id root in WASM using the exact v1 parameters and deterministic message-ID salt.
5. Use native Web Crypto for HKDF-SHA-256 and AES-256-GCM.
6. Decrypt and validate the manifest before parsing attachment frames.
7. Render image, audio, video, text, and generic-download attachments from encrypted manifest metadata.
8. Derive the same deletion capability when the recipient chooses manual deletion.
9. Create browser messages using this same envelope and send `X-Wipe-Client: web`.

Use the deterministic vector in `protocol-v1.md` to prove Go-to-browser interoperability before deployment.

## Replace the current unreleased browser format

Do not keep two cipher formats. Replace the current browser implementation that uses 22-character base64url IDs, 32-byte base64url fragments, `/m/{id}` links, and a single JSON AES-GCM blob. Update it to the unified 12/16-character Base58 link and the envelope in `protocol-v1.md`.

If development data exists in D1/R2, remove or migrate it during deployment. There is no requirement to retain compatibility with an unreleased format.

## Size and quota changes

The existing anonymous 3 MiB maximum makes file attachments impractical and is smaller than one full 4 MiB plaintext chunk. Choose and publish a v1 encrypted-message limit appropriate to the service budget. Keep request streaming and reject oversized bodies before object persistence. The CLI will surface `413` responses.

Keep rate and byte quotas, but update OpenAPI examples and limits to match the chosen v1 policy.

## OpenAPI changes

Update the canonical backend OpenAPI document:

- replace the old ID pattern with 12-character Base58BTC
- keep cipher version `1` as the single unified format
- document optional `X-Wipe-Client` values without making them cryptographic
- document the v1 deletion verifier behavior
- retain all required create headers
- document the configured v1 size limit
- keep `{id, created}` as the create response
- add retrieval only after it exists
- document `DELETE` as idempotent

Run the backend's `npm run openapi:lint` after editing.

## Required tests

- accepts a canonical 12-character Base58 ID
- rejects dashes and excluded Base58 characters in the API path
- accepts cipher version 1 from both `cli` and `web` producers
- create retry is idempotent by size and hash
- collision with different metadata returns `409`
- deletion succeeds with the derived capability
- wrong deletion capability returns `403` without deleting
- unknown deletion returns success
- backend never stores the secret or an encryption key
- expiry cleanup removes object and row
- concurrent wipe-on-read claims produce exactly one winner
- configured byte and rate limits remain enforced

The complete binary and key schedule is in [protocol-v1.md](protocol-v1.md), including a deterministic interoperability vector.
