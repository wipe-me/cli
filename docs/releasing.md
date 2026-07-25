# Releasing wipeme

Releases are built by GoReleaser when a `v*` tag is pushed. A release contains:

- macOS and Linux archives for AMD64 and ARM64
- Debian and RPM packages for AMD64 and ARM64
- SHA-256 checksums covering every downloadable artifact
- a generated Homebrew cask

## Homebrew tap setup

The public tap lives at `wipe-me/homebrew-tap`. Stable releases publish the cask
automatically when the `cli` repository has an Actions secret named
`HOMEBREW_TAP_GITHUB_TOKEN`. Use a fine-grained GitHub token with:

- repository access limited to `wipe-me/homebrew-tap`
- `Contents: Read and write`

GoReleaser intentionally skips automatic tap publication for prerelease tags such
as `v0.1.0-alpha.1`. Publish the generated `dist/wipeme.rb` to
`homebrew-tap/Casks/wipeme.rb` after the GitHub prerelease assets are available.

## Release checklist

1. Ensure `main` is clean and synchronized with `origin/main`.
2. Run `gofmt`, `go test ./...`, and `go vet ./...`.
3. Validate the release configuration with `goreleaser check`.
4. Build a local snapshot with `goreleaser release --snapshot --clean`.
5. Inspect the archives, `.deb`, `.rpm`, generated cask, and checksums in `dist/`.
6. Create and push an annotated tag, for example:

   ```sh
   git tag -a v0.1.0-alpha.1 -m "wipeme v0.1.0-alpha.1"
   git push origin v0.1.0-alpha.1
   ```

7. Wait for the release workflow and verify every asset on GitHub.
8. For a prerelease, publish the generated cask to the tap manually and test
   `brew install --cask wipe-me/tap/wipeme`.

Do not move or recreate a published tag. Fix release failures with a new prerelease
version unless the failed tag never produced public artifacts.
