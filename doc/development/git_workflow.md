# Git Workflow

## Branching Strategy

```
main ────────────────────────── release ──── tag v0.1.0
  │
  └── dev ────────────────────── active development
        │
        ├── feat/crypto-identity    feature branch
        ├── feat/p2p-kademlia
        └── fix/handshake-timeout
```

| Branch | 用途 | 生命周期 |
|--------|------|---------|
| `main` | 稳定发布，从 `dev` 合入 | 永久 |
| `dev` | 活跃开发，所有 PR 的目标分支 | 永久 |
| `feat/*` | 功能开发，完成后 PR 合入 `dev` | 短暂 |
| `fix/*` | Bug 修复 | 短暂 |
| `hotfix/*` | `main` 上的紧急修复，同时合入 `dev` | 短暂 |
| `docs/*` | 文档更新 | 短暂 |

### Branch 命名

```
feat/<scope>-<brief-description>
fix/<scope>-<brief-description>
hotfix/<brief-description>
docs/<brief-description>

示例:
feat/crypto-identity
feat/p2p-kademlia
fix/handshake-timeout
hotfix/crash-on-invalid-key
docs/update-reference
```

## Commit Conventions

遵循 [Conventional Commits](https://www.conventionalcommits.org/)：

```
type(scope): description

feat(pqc): add ML-KEM-768 key generation
fix(network): handle QUIC handshake timeout
docs(api): update IPC interface spec
refactor(crypto): extract hybrid KEM into separate module
chore(deps): bump ml-kem to 0.2.0
```

### Type 列表

| Type | 用途 | 示例 |
|------|------|------|
| `feat` | 新功能 | `feat(identity): add Ed25519 keypair generation` |
| `fix` | Bug 修复 | `fix(handshake): reject zero-length peer ID` |
| `refactor` | 重构（不改变行为） | `refactor(crypto): extract shared secret derivation` |
| `docs` | 文档更新 | `docs(readme): add build instructions` |
| `test` | 测试相关 | `test(crypto): add conformance vectors for ML-KEM` |
| `chore` | 构建/工具/依赖 | `chore(deps): bump libp2p to 0.54` |
| `perf` | 性能优化 | `perf(dht): cache routing table lookups` |
| `ci` | CI/CD 变更 | `ci: add cross-compile job for linux-gnu` |

### Scope 列表

| Scope | 对应模块 |
|-------|---------|
| `pqc` | 后量子密码学 (ML-KEM, ML-DSA) |
| `crypto` | 密码学通用 |
| `identity` | 身份管理 |
| `message` | 消息协议 |
| `network` | libp2p / QUIC |
| `dht` | Kademlia DHT |
| `cli` | 命令行界面 |
| `tauri` | Tauri 壳 / 前端 |
| `deps` | 依赖管理 |
| `ci` | CI/CD |

### Commit 规则

- 使用英文，动词开头，现在时或祈使句：`add`, `fix`, `extract`, `update`
- description 不超过 72 字符
- 禁止 `wip`, `update`, `changes`, `fix bug` 等模糊描述
- 一个 commit 只做一件事（原子性）

## Pull Requests

1. 从 `feat/*` / `fix/*` 发起 PR，目标分支为 `dev`
2. PR 描述包含：做了什么、为什么、影响范围
3. CI 全部通过才能合并
4. Squash merge 保持 `dev` 历史整洁

## Release

1. 从 `dev` 合入 `main`（squash merge 或 merge commit）
2. 打 tag：`v0.1.0`, `v0.2.0`（遵循 [Semantic Versioning](https://semver.org/)）
3. Tag message 简述本版本变更
