# wipe.me unified encrypted envelope v1

The canonical protocol specification is maintained by the reusable Wipe.me SDK:

- [Unified encrypted envelope v1](https://github.com/wipe-me/sdk/blob/main/specification/protocol-v1.md)
- [Cross-language v1 fixtures](https://github.com/wipe-me/sdk/tree/main/fixtures/v1)
- [Go SDK package](https://pkg.go.dev/github.com/wipe-me/sdk/go/wipeme)

The CLI imports `github.com/wipe-me/sdk/go/wipeme` for Base58 capabilities,
private-link parsing and formatting, encryption, deletion-key derivation, and API
requests. Protocol changes belong in the SDK first and reach the CLI through a
versioned SDK release.
