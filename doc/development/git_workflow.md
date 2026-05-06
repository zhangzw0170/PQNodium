# Git Workflow

## Branching Strategy
- `dev`: Active development branch. All PRs target this.
- `main`: Stable releases. Merged from `dev` during releases.
- `feature/*`: Short-lived feature branches.

## Commit Conventions
Use [Conventional Commits](https://www.conventionalcommits.org/):
```
type(scope): description

feat(pqc): add ML-KEM key generation
fix(network): handle QUIC handshake timeout
docs(api): update IPC interface spec
```

## Pull Requests
1. Target `dev`.
2. Require 1 review (or CI pass for solo dev).
3. Squash merge to keep history clean.
