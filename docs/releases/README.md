# Release notes and qualification

Keep user-facing notes in `docs/releases/<tag>.md`. The tag workflow uses that
file as the release body when present and appends generated GitHub notes.
Versioned notes must describe behavior and migration requirements explicitly;
PR titles alone do not record compatibility changes.

For a release from the signing stack:

1. Merge PRs from the bottom of the stack upward. If a PR is squash-merged,
   restack its descendants and check their bases before continuing.
2. On the final source, run `go test ./...`, `go build ./...`, `go vet ./...`
   and `go vet -tags hardware ./integration`.
3. Run the explicit hardware suite on the designated test matrix. Record the
   device model, full firmware qualifier, applet version, interface, key,
   slot, scheme and independent verifier in the
   [qualification record](../signing-qualification.md). A successful compile
   check is not hardware qualification.
4. Check the versioned notes and supported/unknown/pending matrix, then create
   the release tag after the source is merged.
5. Update Goodkey App to the concrete tag in its own dependency change; do not
   depend on an unpinned local replacement or edits to a module cache.

The [v0.5.0 notes](v0.5.0.md) document the signing API and migration changes.
Maintaining these files does not create or publish a tag.
