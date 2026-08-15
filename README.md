# wipeme

Create, consume, and safely inject private one-time [wipe.me](https://wipe.me) messages from terminals, agents, containers, and CI/CD.

```console
$ wipeme
Enter a private message. Press Ctrl-D on an empty line when finished:
Meet me at 9
<Ctrl-D>
https://wipe.me/1K7-mQ2-xR8#7YW-HMf-k9J-CB7
```

`wipeme` encrypts everything locally. The service receives an opaque encrypted envelope and the 9-character automatic message ID, but the 12-character Base58 secret stays after the URL's `#` fragment and is never sent in HTTP requests. Manual-passphrase links use an 8-character ID and no fragment; the separately agreed passphrase may have any Unicode form from 8 through 256 characters.

> [!WARNING]
> This is a development preview. The unified v1 envelope has not received an independent security audit and may change before the first stable release.

The source tree reports `0.2.2-alpha.1-dev`; tagged builds report their exact version
through release-time linker flags.

## Usage

```text
wipeme [options] [file ...]
wipeme read [options] <private-link>
wipeme exec [options] <private-link> -- <command> [args...]
wipeme delete [options] <private-link>
```

Always quote links containing `#`, because shells otherwise interpret the fragment as a comment.

### Read and exec for agents

Consume and print the first readable block:

```sh
wipeme read --non-interactive 'https://wipe.me/1K7-mQ2-xR8#7YW-HMf-k9J-CB7'
```

For manual-passphrase messages, keep credentials out of arguments and use a file or environment source:

```sh
WIPEME_PASSPHRASE='previously agreed phrase' \
  wipeme read --non-interactive 'https://wipe.me/aBc1-dEf2'
```

Inject the first readable block directly into a child environment without inserting a shell:

```sh
wipeme exec --non-interactive --link-file /run/secrets/wipeme-link \
  --set-env STRIPE_API_KEY -- stripe customers list
```

Available passphrases are tried locally in this order: fragment, `--passphrase-file`, `--passphrase-stdin`, `--passphrase-env`, `WIPEME_PASSPHRASE`, then up to three hidden terminal prompts. The encrypted message is retrieved only once. Prefer file or environment sources for automation; `--passphrase-stdin` is intentionally rejected for `exec` because it conflicts with child stdin.

`read` consumes the one-time server copy before local decryption, matching the current service protocol. It intentionally exposes selected plaintext on stdout. Use `--output`, `--output-dir`, or `--json` when appropriate; secret files are created with mode 0600 and are never overwritten.

Stable agent-facing exit codes are `2` for invalid usage, `3` for an invalid link,
`4` when no credential is available, `5` when credentials fail, `6` for retrieval,
`8` for refused output, and `9` when a child cannot be launched. A started child’s
own exit status is propagated directly; other failures use `1`.

### Create with a manual passphrase

Set `WIPEME_PASSPHRASE` while creating to select manual-passphrase mode. The
passphrase may contain arbitrary Unicode text from 8 through 256 characters and is
not included in the resulting link:

```sh
WIPEME_PASSPHRASE='previously agreed phrase' wipeme
# https://wipe.me/aBc1-dEf2
```

An explicitly set `WIPEME_PASSPHRASE` always selects manual mode. Leave it unset
to create an automatic `3-3-3#3-3-3-3` link. The environment value is removed
before any generated-password child command is launched.

### Generate and transfer a password

```sh
wipeme --generate-pass --length 32 --chars portable

wipeme --generate-pass --set-env DATABASE_PASSWORD \
  --link-file ./database-password.link -- ./initialize-database
```

The password is generated with OS cryptographic randomness, placed in the first ordinary text block, encrypted, and never printed. Presets are `portable`, `alnum`, `base58`, `base64url`, `hex`, `digits`, `letters`, and `ascii`; `--alphabet` supplies a validated custom printable ASCII alphabet. During child execution stdout belongs only to the child. Without `--link-file` or `--copy`, the labelled private link is written to stderr.

### Interactive

Run `wipeme` and enter a multiline private message. Press Ctrl-D on an empty line when finished:

```console
$ wipeme --expires 1h
Enter a private message. Press Ctrl-D on an empty line when finished:
Temporary credentials
<Ctrl-D>
https://wipe.me/1K7-mQ2-xR8#7YW-HMf-k9J-CB7
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

# Print a scannable terminal QR code after the link
wipeme --qr

# Swap QR module colors if the terminal background needs it
wipeme --qr --qr-invert

# Machine-readable creation result
wipeme --json

# Save an explicit creator receipt with mode 0600
wipeme --receipt ./private-note.receipt.json

# Anyone holding the complete link can delete the message
printf '%s' "$PRIVATE_LINK" | wipeme delete
```

Run `wipeme --help` or `wipeme delete --help` for the complete command reference.

`--qr` leaves the private link as the first output line and prints a compact QR code
below it. The QR contains the complete private link, including its fragment secret
for automatic-key messages. Treat screenshots and terminal recordings containing
it as secrets. Manual-passphrase QR codes contain only the public link; recipients
must still enter the separately shared passphrase. QR output is intentionally
incompatible with `--json` so machine-readable stdout remains stable. The renderer
uses the terminal's existing foreground and background instead of forcing ANSI
colors; use `--qr-invert` if the module orientation does not suit the terminal
theme or recording.

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

### Homebrew

Install the macOS binary from the official Wipe.me tap:

```sh
brew install --cask wipe-me/tap/wipeme
```

### Debian and Ubuntu

The current CLI release is a preview. Add the signed Wipe.me preview repository
once, then install and update `wipeme` normally with APT:

```sh
sudo install -d -m 0755 /usr/share/keyrings
curl -fsSL https://packages.wipe.me/keys/wipeme-packages.gpg |
  sudo tee /usr/share/keyrings/wipeme-packages.gpg >/dev/null
curl -fsSL https://packages.wipe.me/apt/wipeme-preview.sources |
  sudo tee /etc/apt/sources.list.d/wipeme.sources >/dev/null
sudo apt update
sudo apt install wipeme
```

### Fedora, RHEL, and compatible distributions

Add the signed Wipe.me preview repository once, then install with DNF:

```sh
sudo curl -fsSL \
  https://packages.wipe.me/rpm/wipeme-preview.repo \
  -o /etc/yum.repos.d/wipeme.repo
sudo dnf install wipeme
```

Both repositories support AMD64/x86-64 and ARM64/AArch64. The repository signing
key fingerprint is:

```text
C83C 58D4 F446 BB20 24E4  2CA1 DEC6 6000 6BED 76F6
```

Preview packages never enter the stable channel automatically. When a stable CLI
release is available, the installation instructions will switch to the stable
repository.

### Direct downloads, archives, and Go

Prebuilt macOS and Linux archives, SHA-256 checksums, `.deb` packages, and `.rpm`
packages are attached to tagged
[GitHub releases](https://github.com/wipe-me/cli/releases). You can build the next
prerelease from `main` with Go 1.25 or newer:

```sh
go install github.com/wipe-me/cli/cmd/wipeme@main
wipeme --version
# wipeme 0.2.2-alpha.1-dev
```

Verify any downloaded release artifact against `checksums.txt` before installing it.

## Link format

```text
Automatic: https://wipe.me/1K7-mQ2-xR8#7YW-HMf-k9J-CB7
Manual:    https://wipe.me/aBc1-dEf2
```

- Automatic message ID: 9 Base58BTC characters, displayed as `3-3-3`
- Automatic fragment secret: 12 uniformly random Base58BTC characters, displayed as `3-3-3-3`
- Manual-passphrase message ID: 8 Base58BTC characters, displayed as `4-4`, with no passphrase in the link
- Dashes and spaces are presentation separators; Base58 remains case-sensitive
- The automatic fragment has approximately 70 bits of entropy
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

Before encryption, the CLI automatically removes supported private metadata from a
temporary local copy:

- JPEG/JPG: APP1 EXIF/XMP, APP13 IPTC/Photoshop metadata, and comments
- PNG/APNG: `eXIf`, `iTXt`, `tEXt`, `zTXt`, `tIME`, and `pHYs` chunks
- WebP: EXIF and XMP chunks and their VP8X feature flags
- MP3: ID3v2 and ID3v1 tags

Pixel data, JPEG JFIF and ICC/color data, PNG/APNG color and animation chunks,
WebP ICC, alpha and animation data, and MP3 audio frames remain unchanged. Original
files are never modified. Unsupported formats—including PDF, Office documents,
archives, video containers, and audio formats other than MP3—are encrypted
byte-for-byte; sanitize those files separately when their embedded metadata is a
concern.

Cleanup and encryption happen locally and do not use a third-party processing
service. The CLI does not invoke FFmpeg and has no native runtime dependencies.
Image dimensions are extracted for supported Go image formats; richer audio/video
metadata can be calculated by the web client after decryption.

## API

The default create endpoint is:

```http
PUT https://wipe.me/api/messages/1K7mQ2xR8
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
  "id": "1K7mQ2xR8",
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

The server receives a derived deletion capability during creation and never receives the short secret, manual passphrase, Argon2id root, or encryption keys. A complete automatic link grants read and deletion authority. A manual `4-4` link also requires its separately shared passphrase. `wipeme delete` reconstructs the deletion capability locally.

`--receipt` saves the private link and its canonical creator credential. In manual mode that credential is the passphrase. Receipts are created with mode `0600`, refuse to overwrite an existing file, and must be protected like the recipient link itself.

## License

Apache-2.0
