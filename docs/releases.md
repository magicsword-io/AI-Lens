# Native releases

[Download the current release](https://github.com/magicsword-io/AI-Lens/releases/latest)
or use the [setup guide](https://magicsword-io.github.io/AI-Lens/getting-started/).
ZIPs currently target Windows x64, Linux x64 and macOS Apple Silicon. Other
architectures require a source build. Packages are unsigned.

## Publish a version

1. Update the workspace version in `Cargo.toml` and both workspace entries in
   `Cargo.lock`. Add `docs/releases/vX.Y.Z.md` and update the website's central
   release data and README links.
2. Review and merge the change into main after native and website checks pass.
3. Tag that main commit and push the tag: `git tag vX.Y.Z COMMIT`, then
   `git push https://github.com/magicsword-io/AI-Lens.git vX.Y.Z`.
4. Once Release succeeds, run `gh workflow run pages.yml --repo magicsword-io/AI-Lens --ref main`.
   Website publication waits for that version's public ZIPs and checksums, so
   a version bump never replaces the live site with unavailable download links.

The Release workflow validates the tag/version and main ancestry, then calls the
same native and website CI used for pull requests. It packages and runs the
extracted CLI with its adjacent engine on each platform. Publication waits for
every job to pass, verifies the three package checksums and build identities,
creates a draft, uploads all ZIPs plus aggregate checksums/provenance, and
publishes it. It never overwrites an existing release.

Only the publisher receives release-write permission. Artifacts come from that
workflow run, not a pull-request or a separately selected build. Re-run a failed
build only after diagnosing its first failure. If upload fails, inspect and
remove the incomplete draft before a deliberate retry; published versions must
never silently change. Withdraw a faulty release and publish a new version.

Build provenance records the exact source, Cargo.lock hash, compiler, runner
image, architecture, native binary/library hashes and ZIP hashes. These records
and SHA256SUMS identify artifacts; they do not provide code signing or notarization.
