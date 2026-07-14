# Contributing

Thanks for helping improve `wipeme`.

1. Open an issue before changing the encrypted envelope or public API contract.
2. Keep the CLI dependency-light and compatible with `CGO_ENABLED=0`.
3. Add tests for behavior changes and interoperability vectors for protocol changes.
4. Run `gofmt -w .`, `go test ./...`, and `go vet ./...` before opening a pull request.

Security issues should not be filed publicly. Use GitHub's private vulnerability reporting for this repository.
