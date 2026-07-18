# wipeme

Create private, one-time [wipe.me](https://wipe.me) links from your terminal—text, files, images, audio, and more.

```console
$ wipeme
Enter a private message. Press Ctrl-D on an empty line when finished:
Meet me at 9
<Ctrl-D>
https://wipe.me/1K7m-Q2xR-8VpC#7YWH-Mfk9-JCB7-P4eG
```

`wipeme` encrypts everything locally. The service receives an opaque encrypted envelope and the 12-character message ID, but the 16-character Base58 secret stays after the URL's `#` fragment and is not sent in HTTP requests.

> [!WARNING]
> This is a development preview. The unified v1 envelope has not received an independent security audit and may change before the first stable release.

## Usage

### Interactive

Run `wipeme` and enter a multiline private message. Press Ctrl-D on an empty line when finished:

```console
$ wipeme --expires 1h
Enter a private message. Press Ctrl-D on an empty line when finished:
Temporary credentials
<Ctrl-D>
https://wipe.me/1K7m-Q2xR-8VpC#7YWH-Mfk9-JCB7-P4eG
```

The message is read from the terminal rather than a command argument, so its contents are not added to shell history.

### Attachments

```sh
# One attachment
wipeme screenshot.png

# Multiple attachments
wipeme photo.jpg recording.m4a report.pdf

# Message from a file plus attachments
wipeme --message-file note.txt photo.jpg recording.m4a

# Treat stdin as an attachment instead of a message
generate-report | wipeme --attach - --name report.pdf --type application/pdf
```

Positional paths are attachments. Standard input is the message unless `--attach -` explicitly treats it as a file.

### Automation and pipelines

`wipeme` composes with commands that produce secrets or private content:

```sh
# Existing file as the message
wipeme < private-note.txt

# Secret produced by another command
password-manager read service/account | wipeme --expires 1h

# Existing shell variable; the value itself is not written into shell history
printf '%s' "$SECRET" | wipeme --expires 1h

# Piped message plus attachments
printf '%s' "$NOTE" | wipeme photo.jpg recording.m4a
```

Avoid putting literal secrets in command arguments or pipeline commands. Both of these may expose the value through shell history or process inspection:

```sh
# Avoid
wipeme --message 'literal secret'
printf '%s' 'literal secret' | wipeme
```

### Output and management

```sh
# Copy the link without printing it
wipeme --copy

# Machine-readable creation result
wipeme --json

# Save an explicit creator receipt with mode 0600
wipeme --receipt ./private-note.receipt.json

# Anyone holding the complete link can delete the message
printf '%s' "$PRIVATE_LINK" | wipeme delete
```

Run `wipeme --help` or `wipeme delete --help` for the complete command reference.

## Configuration

Optional YAML configuration can be stored for all users or for the current user:

```text
/etc/wipeme/config.yaml
~/.wipeme/config.yaml
```

The user file overrides the system file. A minimal configuration usually needs
only the shared server URL:

```yaml
server_url: https://wipe.me
expires: 24h
copy: false
```

Both the API and public link site inherit `server_url`. For split development
servers, `api_url` and `site_url` can override them independently. Configuration
priority is: command flags, environment variables, user file, system file, then
built-in defaults.

Use a specific file with `--config ./config.yaml` or `WIPEME_CONFIG`. Environment
configuration supports `WIPEME_SERVER_URL`, `WIPEME_API_URL`, `WIPEME_SITE_URL`,
`WIPEME_EXPIRES`, and `WIPEME_COPY`. `WIPEME_API_URL` and `WIPEME_SITE_URL` remain
separate so local API and frontend development servers can use different ports.
Configuration files are for preferences only; do not store private links, secrets,
deletion keys, or creator receipts in them.

### Progress

When stderr is an interactive terminal, the CLI uses byte-based SDK progress events
to update one line during encryption and upload:

```text
Encrypting... ▰▰▰▱▱▱▱▱▱▱▱▱  25%
Uploading...  ▰▰▰▰▰▰▰▰▰▱▱▱  75%
```

The uploading phase replaces the encryption phase on the same line. Progress is
automatically hidden when stderr is redirected or when `--json` is used, so stdout
and pipelines remain clean.

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
- AES-256-GCM encrypts the manifest and independently authenticates attachment chunks (512 KiB by default)
- Filenames, messages, MIME types, media classification, dimensions, and sizes are encrypted

The reusable [Wipe.me SDK](https://github.com/wipe-me/sdk) owns the cryptographic
implementation and canonical [protocol v1 specification](https://github.com/wipe-me/sdk/blob/main/specification/protocol-v1.md).
The CLI adds terminal input, local media inspection, receipts, and output behavior
on top of the Go SDK. Backend integration notes are in
[docs/backend-v1-handoff.md](docs/backend-v1-handoff.md).

Free anonymous uploads are limited to a 3 MiB encrypted envelope and a maximum expiry
of 14 days. Every message is claimed at most once.

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
  WIPEME_SERVER_URL=http://localhost:5173 \
  WIPEME_API_URL=http://localhost:8787/api/messages \
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
