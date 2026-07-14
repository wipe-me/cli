# wipe.me unified encrypted envelope v1

Status: development preview. All multibyte integers are unsigned and encoded in network byte order (big-endian).

## Link

```text
https://wipe.me/<message-id>#<secret>
```

Both values use the Base58BTC alphabet:

```text
123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz
```

The canonical message ID is 12 characters. The canonical secret is 16 characters. ASCII `-` and space characters are ignored as presentation separators. Letter case is significant.

Only the canonical secret bytes—not its dashed presentation—are passed to Argon2id. The fragment is never part of the API request. The canonical message ID is generated before encryption and supplies unique public context for key derivation.

## Cryptographic primitives

| Purpose | Primitive | v1 parameters |
|---|---|---|
| Root key derivation | Argon2id v1.3 | 64 MiB, 3 iterations, parallelism 1, deterministic 32-byte salt, 32-byte output |
| Capability separation | HKDF-SHA-256 | Separate encryption and deletion branches, empty HKDF salt, 32-byte outputs |
| Encryption subkeys | HKDF-SHA-256 | Separate manifest and per-attachment keys |
| Encryption | AES-256-GCM | 12-byte nonce, 16-byte tag |
| Attachment chunks | AES-256-GCM | Independently authenticated, 4,194,304 plaintext bytes maximum |

The secret contains approximately 93.7 bits of entropy. Deriving 256-bit keys does not change that entropy; Argon2id raises the cost of offline guesses.

Argon2id salt:

```text
SHA-256(UTF-8("wipe.me/envelope/v1/kdf-salt/") || canonical_message_id)
```

### HKDF info

Encryption root:

```text
UTF-8("wipe.me/envelope/v1/encryption")
```

Deletion capability:

```text
UTF-8("wipe.me/envelope/v1/deletion")
```

Both are derived directly from the Argon2id root. The server receives the deletion capability but never the Argon2id root or encryption root.

Manifest key, derived from the encryption root:

```text
UTF-8("wipe.me/envelope/v1/manifest")
```

Attachment key, derived from the encryption root:

```text
UTF-8("wipe.me/envelope/v1/attachment/") || attachment_id
```

`attachment_id` is the raw 16-byte value, not its hexadecimal representation.

## Binary envelope

### Public header

| Offset | Size | Value |
|---:|---:|---|
| 0 | 8 | `57 49 50 45 4d 45 00 01` (`WIPEME`, NUL, version 1) |
| 8 | 4 | Argon2id memory cost in KiB |
| 12 | 4 | Argon2id iteration count |
| 16 | 1 | Argon2id parallelism |
| 17 | 32 | Deterministic Argon2id salt derived from the message ID |
| 49 | 12 | Random manifest AES-GCM nonce |
| 61 | 4 | Encrypted manifest length, including GCM tag |
| 65 | variable | Encrypted manifest |

The first 61 bytes are the manifest AES-GCM additional authenticated data (AAD). A decryptor must recompute the salt from the message ID and reject a mismatch before running Argon2id.

### Encrypted manifest

The plaintext is compact UTF-8 JSON:

```json
{
    "version": 1,
  "message": "Listen to this",
  "chunk_size": 4194304,
  "attachments": [
    {
      "id": "00112233445566778899aabbccddeeff",
      "name": "recording.m4a",
      "type": "audio/mp4",
      "kind": "audio",
      "size": 1938201,
      "chunks": 1,
      "nonce_prefix": "814c2a197703d8bb"
    }
  ]
}
```

Attachment IDs and nonce prefixes use lowercase hexadecimal inside the encrypted JSON. `width` and `height` are optional positive integers for recognized images.

### Attachment frame

Attachments occur in manifest order and chunks occur in increasing index order.

| Size | Value |
|---:|---|
| 1 | Frame type `0x01` |
| 4 | Zero-based attachment index |
| 4 | Zero-based chunk index |
| 4 | Plaintext length |
| plaintext length + 16 | AES-GCM ciphertext and tag |

The 13-byte frame header is serialized before its ciphertext.

Attachment nonce:

```text
8-byte random nonce_prefix || uint32(chunk_index)
```

Attachment AAD:

```text
8-byte envelope magic/version
|| 13-byte frame header
|| uint32(total attachment chunks)
|| 16-byte attachment_id
```

An empty file has zero chunks. The envelope ends with a single `0x00` frame byte. Extra bytes after the end frame are invalid.

## API contract

Create:

```http
PUT /api/messages/{canonical-message-id}
Content-Type: application/octet-stream
Accept: application/json
X-Wipe-Content-Hash: <lowercase hex SHA-256 of the complete envelope>
X-Wipe-Deletion-Key: <unpadded base64url 32-byte deletion capability>
X-Wipe-Cipher-Version: 1
X-Wipe-Client: cli
X-Wipe-Expires-At: <Unix epoch milliseconds>
X-Wipe-On-Read: 1
```

The body is the binary envelope. The client generates the canonical, ungrouped 12-character Base58BTC ID. A successful server confirms it:

```json
{
  "id": "1K7mQ2xR8VpC",
  "created": true
}
```

The storage service must treat the envelope as opaque bytes. It must not receive or derive the URL-fragment secret, root key, or encryption keys. It stores a deletion-key verifier alongside the message and uses it to authorize:

```http
DELETE /api/messages/{canonical-message-id}
X-Wipe-Deletion-Key: <unpadded base64url deletion capability>
```

Deletion is idempotent. A missing message returns `200 {"deleted":true}`.

## Creator receipts

A creator receipt contains the complete recipient link, canonical message ID, canonical secret, cipher version, and expiration. It does not need a separate privileged token: the deletion capability is reproducibly derived from the ID and secret. Receipt files must be created with user-only permissions and must not be uploaded.

## Parser requirements

Implementations must:

1. Reject unsupported magic or versions.
2. Bound public KDF parameters before allocating memory.
3. Authenticate and validate the manifest before processing attachment frames.
4. Reject missing, duplicate, reordered, or out-of-range frames.
5. Reject chunk lengths above 4 MiB.
6. Reject attachment byte totals that differ from the encrypted manifest.
7. Reject missing end frames and trailing data.
8. Return the same generic user-facing error for an incorrect secret and damaged ciphertext.

Implementations must never reuse a nonce with the same derived key.

## Interoperability vector

This compact vector uses deliberately cheap Argon2id settings so it can run in every test suite. It must never be used as a production parameter recommendation.

```text
Message ID:   1K7mQ2xR8VpC
Secret:       7YWHMfk9JCB7P4eG
Message:      hello from wipe.me
Random bytes: repeated 0x2a
Memory:       64 KiB
Iterations:   1
Parallelism:  1
Attachments:  none
```

Expected envelope, standard Base64 encoding:

```text
V0lQRU1FAAEAAABAAAAAAQHnsKMnU1nKpNxAqulNd67mWzZk7bpqURo688A/rz//5yoqKioqKioqKioqKgAAAFGF2i2ruMvJ9UjmwemeGqhZOX5P5nWTzeB2MoO3WBXtd289DLl7Fhg5cwD6uAM2aXUheTLm4ZEafRJf3u2FzOgPgEZCOTCfWPkJio/RXkBxctkA
```
