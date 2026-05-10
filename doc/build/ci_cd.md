# CI/CD Configuration

## GitHub Actions

### Workflows
1.  **lint.yml**: `cargo fmt --check`, `cargo clippy`.
2.  **test.yml**: `cargo test`.
3.  **build.yml**: Build for `x86_64-pc-windows-msvc` and `x86_64-unknown-linux-gnu`.
4.  **audit.yml**: Run `cargo audit` for security vulnerabilities.

## Local Pre-Commit
- Use a git hook to run `cargo fmt --check && cargo clippy && cargo test` before committing.
