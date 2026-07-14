# wipeme

Create private, one-time [wipe.me](https://wipe.me) links from your terminal—text, files, images, audio, and more.

```console
$ printf '%s' 'Meet me at 9' | wipeme
https://wipe.me/1K7m-Q2xR-8VpC#7YWH-Mfk9-JCB7-P4eG
```

`wipeme` encrypts everything locally. The service receives an opaque encrypted envelope and the 12-character message ID, but the 16-character Base58 secret stays after the URL's `#` fragment and is not sent in HTTP requests.

> [!WARNING]
> This is a development preview. The unified v1 envelope has not received an independent security audit and may change before the first stable release.

## Usage

Standard input is the optional message; positional paths are attachments:

```sh
# Text
printf '%s' 'The password is swordfish' | wipeme

# One attachment
wipeme screenshot.png

# Text plus multiple attachments
printf '%s' 'Here are the files' | wipeme photo.jpg recording.m4a report.pdf

# Treat stdin as an attachment instead of a message
generate-report | wipeme --attach - --name report.pdf --type application/pdf

# Expire if unopened
printf '%s' 'Temporary credentials' | wipeme --expires 1h

# Copy without printing the link
printf '%s' 'Private note' | wipeme --copy

# Machine-readable output
printf '%s' 'Private note' | wipeme --json

# Save an explicit creator receipt with mode 0600
printf '%s' 'Private note' | wipeme --receipt ./private-note.receipt.json

# Anyone holding the complete link can delete the message
printf '%s' "$PRIVATE_LINK" | wipeme delete
```

Run `wipeme --help` for all options. Avoid `--message` for sensitive values because command arguments may be saved in shell history or exposed to process inspection.

## Installation

Prebuilt macOS and Linux archives will be attached to tagged [GitHub releases](https://github.com/wipe-me/cli/releases). Until the first release, build from source with Go 1.25 or newer:

```sh
go install github.com/wipe-me/cli/cmd/wipeme@latest
```

## Link format

```text
https://wipe.me/1K7m-Q2xR-8VpC#7YWH-Mfk9-JCB7-P4eG
                └ message ID ┘  └──── secret ────┘
```

- Message ID: 12 Base58BTC characters, displayed as `4-4-4`
- Secret: 16 uniformly random Base58BTC characters, displayed as `4-4-4-4`
- Dashes and spaces are presentation separators; Base58 remains case-sensitive
- The secret has approximately 94 bits of entropy
- The message ID supplies deterministic Argon2id salt context
- Argon2id derives a 256-bit root, then HKDF separates encryption and deletion capabilities
- AES-256-GCM encrypts the manifest and independently authenticates 4 MiB chunks
- Filenames, messages, MIME types, media classification, dimensions, and sizes are encrypted

The exact interoperable format is specified in [docs/protocol-v1.md](docs/protocol-v1.md).
The corresponding server and browser contract is in [docs/backend-v1-handoff.md](docs/backend-v1-handoff.md).

## Media handling

Attachments are inspected by content rather than trusting their extensions. Images, audio, video, text, and generic files receive different encrypted presentation metadata so the web client can choose an appropriate viewer after decryption. Unsupported or unknown formats remain generic encrypted downloads.

The CLI does not invoke FFmpeg and has no native runtime dependencies. Image dimensions are extracted for supported Go image formats; richer audio/video metadata can be calculated by the web client after decryption.

## API

The default create endpoint is:

```http
PUT https://wipe.me/api/messages/1K7mQ2xR8VpC
Content-Type: application/octet-stream
X-Wipe-Content-Hash: <sha256>
X-Wipe-Deletion-Key: <base64url-derived-capability>
X-Wipe-Cipher-Version: 1
X-Wipe-Client: cli
X-Wipe-Expires-At: <epoch-milliseconds>
X-Wipe-On-Read: 1
```

Successful response:

```json
{
  "id": "1K7mQ2xR8VpC",
  "created": true
}
```

Development servers can be selected without rebuilding:

```sh
printf '%s' 'local test' | \
  WIPEME_API_URL=http://localhost:8787/api/messages \
  WIPEME_SITE_URL=http://localhost:5173 \
  wipeme
```

## Development

```sh
go test ./...
go vet ./...
go build ./cmd/wipeme
```

The project is intentionally pure Go (`CGO_ENABLED=0`) for portable macOS and Linux binaries.

## Deletion model

The server receives a derived deletion capability during creation and never receives the short secret, Argon2id root, or encryption keys. The same complete private link grants read and deletion authority. `wipeme delete` reconstructs the deletion capability locally from the message ID and secret.

`--receipt` saves the complete private link and its canonical components for the creator. Receipts are created with mode `0600`, refuse to overwrite an existing file, and must be protected like the recipient link itself.

## License

Apache-2.0
