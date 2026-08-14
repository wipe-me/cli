# Releasing wipeme

Releases are built by GoReleaser when a `v*` tag is pushed. A release contains:

- macOS and Linux archives for AMD64 and ARM64
- Debian and RPM packages for AMD64 and ARM64
- SHA-256 checksums covering every downloadable artifact
- a generated Homebrew cask
- signed APT and RPM repositories at `packages.wipe.me`

Source builds use the development version in `cmd/wipeme/main.go` (currently
`0.2.1-alpha.1-dev`). GoReleaser replaces it through `-ldflags -X` with the exact
tag version, so a `v0.2.1-alpha.1` artifact reports `wipeme 0.2.1-alpha.1`.

Release-specific behavior and validation notes live under `docs/releases/`. Review
the matching file before creating a tag.

## Package repository setup

Release workflows publish packages to a private Cloudflare R2 bucket exposed
read-only through `https://packages.wipe.me`.

The GitHub repository requires these Actions secrets:

- `PACKAGES_GPG_PRIVATE_KEY`: ASCII-armored private repository signing key
- `CF_R2_ACCOUNT_ID`: Cloudflare account containing the package bucket
- `CF_R2_ACCESS_KEY_ID`: bucket-scoped R2 write credential
- `CF_R2_SECRET_ACCESS_KEY`: corresponding R2 secret
- `CF_R2_BUCKET`: R2 package bucket name

The public signing key is committed at `packaging/wipeme-packages.asc`. Its
fingerprint is:

```text
C83C 58D4 F446 BB20 24E4  2CA1 DEC6 6000 6BED 76F6
```

The private key must never be committed. Rotate the key before its 2029-07-25
expiration and publish both old and new public keys during the transition.

Tags containing a prerelease suffix publish to the `preview` APT/RPM channel.
Stable semantic-version tags publish to `stable`. Repository publishing is
serialized in GitHub Actions to prevent concurrent metadata updates.

To republish an existing GitHub release, run **Publish package repositories** and
provide its tag and intended channel. This is also the bootstrap path for releases
created before package-repository publishing was enabled.

## Homebrew tap setup

The public tap lives at `wipe-me/homebrew-tap`. Stable releases publish the cask
automatically when the `cli` repository has an Actions secret named
`HOMEBREW_TAP_GITHUB_TOKEN`. Use a fine-grained GitHub token with:

- repository access limited to `wipe-me/homebrew-tap`
- `Contents: Read and write`

GoReleaser intentionally skips automatic tap publication for prerelease tags such
as `v0.2.1-alpha.1`. Publish the generated `dist/wipeme.rb` to
`homebrew-tap/Casks/wipeme.rb` after the GitHub prerelease assets are available.

## Release checklist

1. Ensure `main` is clean and synchronized with `origin/main`.
2. Confirm the source development version names the intended next release, then run
   `gofmt`, `go test ./...`, and `go vet ./...`.
3. Validate the release configuration with `goreleaser check`.
4. Build a local snapshot with `goreleaser release --snapshot --clean`.
5. Inspect the archives, `.deb`, `.rpm`, generated cask, and checksums in `dist/`.
6. Create and push an annotated tag, for example:

   ```sh
   git tag -a v0.2.1-alpha.1 -m "wipeme v0.2.1-alpha.1"
   git push origin v0.2.1-alpha.1
   ```

7. Wait for the release workflow and verify every asset on GitHub.
8. Confirm the APT/RPM repository publication step completed and verify
   `apt-cache policy wipeme` or `dnf info wipeme`.
9. For a prerelease, publish the generated cask to the tap manually and test
   `brew install --cask wipe-me/tap/wipeme`.

Do not move or recreate a published tag. Fix release failures with a new prerelease
version unless the failed tag never produced public artifacts.
