# wipe.me unified encrypted envelope v1

The canonical protocol specification is maintained by the reusable Wipe.me SDK:

- [Unified encrypted envelope v1](https://github.com/wipe-me/sdk/blob/main/specification/protocol-v1.md)
- [Cross-language v1 fixtures](https://github.com/wipe-me/sdk/tree/main/fixtures/v1)
- [Go SDK package](https://pkg.go.dev/github.com/wipe-me/sdk/go/wipeme)

The CLI imports `github.com/wipe-me/sdk/go/wipeme` for Base58 capabilities,
private-link parsing and formatting, encryption, deletion-key derivation, and API
requests. Protocol changes belong in the SDK first and reach the CLI through a
versioned SDK release. CLI `v0.3.0-alpha.3` targets Go SDK
`v0.5.0-alpha.1`, including application-link parsing, compact automatic capability
expansion, manual-passphrase derivation, retrieval, deletion, and chunk progress.

Terminal QR rendering, introduced in CLI `v0.2.1-alpha.1` and refined in
`v0.2.2-alpha.1` and `v0.2.3-alpha.1`, is an output-only feature. It encodes the
already-formatted private link and does not change message IDs, secrets, derivation,
encryption, or the backend API. In `v0.2.3-alpha.1`, `--qr` uses the library's
compact half-block renderer and prints a terminal-compatibility caption, while
`--qr-big` selects its full-size fallback. `--qr-invert` works with either renderer;
the two size flags are mutually exclusive.

CLI `v0.3.0-alpha.3` adds an MCP adapter around the same v1 protocol and SDK. MCP
tools do not introduce new message, link, encryption, attachment, or deletion-key
formats. Inline MCP PNG QR images encode the same already-formatted private link.

The encrypted manifest message remains an Editor.js-style document. Every CLI
attachment has a matching `attachment` block whose zero-based `attachmentIndex`
references the corresponding authenticated SDK attachment frame. Attachment order
is preserved and attachment metadata is never treated as message text.
