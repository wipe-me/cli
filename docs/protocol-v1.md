# wipe.me unified encrypted envelope v1

The canonical protocol specification is maintained by the reusable Wipe.me SDK:

- [Unified encrypted envelope v1](https://github.com/wipe-me/sdk/blob/main/specification/protocol-v1.md)
- [Cross-language v1 fixtures](https://github.com/wipe-me/sdk/tree/main/fixtures/v1)
- [Go SDK package](https://pkg.go.dev/github.com/wipe-me/sdk/go/wipeme)

The CLI imports `github.com/wipe-me/sdk/go/wipeme` for Base58 capabilities,
private-link parsing and formatting, encryption, deletion-key derivation, and API
requests. Protocol changes belong in the SDK first and reach the CLI through a
versioned SDK release. CLI `v0.2.0-alpha.1` targets Go SDK
`v0.5.0-alpha.1`, including application-link parsing, compact automatic capability
expansion, manual-passphrase derivation, retrieval, deletion, and chunk progress.

The encrypted manifest message remains an Editor.js-style document. Every CLI
attachment has a matching `attachment` block whose zero-based `attachmentIndex`
references the corresponding authenticated SDK attachment frame. Attachment order
is preserved and attachment metadata is never treated as message text.
