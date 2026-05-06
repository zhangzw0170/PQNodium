# Release Process

## Versioning
We use Semantic Versioning (SemVer): `MAJOR.MINOR.PATCH`.
- `0.x.x`: Initial development. Breaking changes allowed.
- `1.0.0`: Stable public API.

## Steps
1.  Update `CHANGELOG.md`.
2.  Bump version in `Cargo.toml`.
3.  Create tag: `git tag -a vX.Y.Z -m "Release vX.Y.Z"`.
4.  Push: `git push origin vX.Y.Z`.
5.  GitHub Action publishes artifacts (binaries, Tauri bundles).

## Release Artifacts
- Windows: `PQNodium-x86_64-pc-windows-msvc.zip`
- Linux: `PQNodium-x86_64-unknown-linux-gnu.tar.gz`
- Tauri Bundles: `.exe`, `.msi`, `.AppImage`, `.deb`
