# ZFeiQ 复盘：教训与对 PQNodium 的启示

> **来源项目**: ZFeiQ — 基于 Python/PyQt5 的局域网 IPMSG 即时通讯系统，集成 X25519/ChaCha20 加密、PPOCRv4 OCR、文件传输。
> **项目周期**: 2025-11-18 ~ 2026-01-14（活跃开发约 40 天），已归档。
> **分析日期**: 2026-05-06

---

## 一、项目概况

ZFeiQ 是一个面向嵌入式平台（RK3566）的局域网 P2P 聊天软件，致敬 IPMSG（飞秋/飞鸽传书）协议。项目经历了完全重写（Legacy → NZFeiQ），最终在 Alpha 6.2 归档。

**技术栈**: Python 3.8+ / PyQt5 / UDP 广播 / TCP 文件传输 / X25519 + ChaCha20-Poly1305 / RKNN NPU OCR

**核心架构**: `engine.py`（925 行 God Object）+ `session.py`（加密握手）+ `crypto.py`（密码学原语）+ `gui/bridge.py`（Qt 桥接）

---

## 二、关键教训

### 教训 1：没有身份认证的加密等于没有加密

**发生了什么**: ZFeiQ 生成了 X25519 身份密钥对并持久化到 `identity.bin`，但握手协议中 `fp=` 字段永远为空。身份密钥**生成而未使用**。加密只防被动窃听，任何局域网节点都可以做 MITM。

**更糟糕的是**: 这个问题在开发过程中已被记录（docs/SECURITY.md 标注为"必做"），但直到项目归档也**从未实现**。

**对 PQNodium 的启示**:
- Phase 1 的交付清单加硬约束：**没有身份签名的握手不算完成**
- 不允许出现"先做加密，认证以后补"的中间状态
- 代码 review 时重点检查：身份密钥是否实际参与了握手验证

---

### 教训 2：一天堆出核心架构——不可能有质量

**发生了什么**: 12 月 5 日一天提交了 12 个 commit，内容涵盖：初始化 → 整理目录（×2） → 添加 engine → 添加 session → CLI → 修 linter → 重新整理架构（×2） → 加密升级 → 群组测试 → 修测试。核心架构在一天之内从零搭出。

开发频率分布：
- 11/27: 21 commits
- 12/05: 12 commits
- 12/06: 4 commits
- 其余日期零散

这是典型的赶 deadline 模式（嵌入式课程设计），时间压力导致了所有技术债。

**对 PQNodium 的启示**:
- 每个 phase 内拆成 <1 天的小任务，每个任务有 `cargo test` 验收
- PQNodium 没有课程 deadline，不要给自己设不合理的截止日期
- 每个 phase 预留 buffer 时间

---

### 教训 3：反复整理目录 = 架构在摇摆

**发生了什么**: "整理目录/架构" 相关的 commit 出现了 6 次以上。最大的转折点在 12/08：`MERGE: NZFeiQ (ZFeiQ Refactored) to root`——项目生命周期中做了一次**完全重写**。Legacy 版本归档，新版 NZFeiQ 成为主线。

根本原因：项目初期没有清晰的模块边界，边写边改，改到无法维护后被迫重写。

**对 PQNodium 的启示**:
- PQNodium 现在花时间做架构设计文档是对的——ZFeiQ 就是吃了"先写代码再想架构"的亏
- 但文档不能替代原型验证：建议 Phase 0 结束前做一个**技术验证 spike**（单文件 Rust 程序确认 hybrid KEM 能跑通），验证 trait 设计和 crate 兼容性
- 别等 Phase 1 才发现核心 crate 的 API 跟文档写的不一样

---

### 教训 4：God Object 是项目腐烂的起点

**发生了什么**: `engine.py` 925 行，承担了消息收发、群组管理、文件传输、OCR、截图、加密握手、配置持久化、网络检测、后台维护。GUI bridge 直接访问 engine 的私有属性（`self.core._save_config()`、`self.core._get_session()`），导致 engine 内部任何重构都会崩 GUI。

依赖拓扑是星形：所有模块只跟 engine 耦合，engine 跟所有模块耦合。这不是"模块化"，是"中心化单点"。

**对 PQNodium 的启示**:
- `pqnodium-core` 内部需要更细的边界：

```
core/
├── crypto/       # 只管密码学原语，不管握手状态机
├── identity/     # 身份管理、密钥存储（不碰网络）
├── session/      # 握手状态机（调用 crypto traits，不直接碰 crate）
├── message/      # 消息编解码
├── state/        # 会话状态、联系人注册
```

- 模块间只通过公共 trait 交互，Rust 的 `pub` 可见性天然强制这一点
- Tauri IPC 层只通过 `pqnodium-p2p` 的公共 API 调用，禁止访问内部私有函数

---

### 教训 5：静默吞错比报错更危险

**发生了什么**: `except: pass` 在 engine.py 中出现了 **14 次以上**。加密失败、配置损坏、网络错误全部静默丢弃。用户看到"发送成功"但消息根本没到，调试时完全无法定位问题。

GUI bridge 中的 `_on_core_event`（100+ 行）也是同样模式：根据日志文本字符串匹配来触发信号（如扫描 "Screenshot saved"），极其脆弱。

**对 PQNodium 的启示**:
- `pqnodium-core` 中所有 fallible 函数返回 `Result<T, E>`，禁止 unwrap 或静默忽略
- 禁止 bare `catch_all`，除非有明确的日志输出
- 加密操作失败必须返回 Error，禁止 fallback 到明文（与零降级策略一致）
- 用 Rust 的类型系统强制：编译期就能排除 ZFeiQ 的 `except: pass` 模式

---

### 教训 6：测试零覆盖 = 黑箱运行

**发生了什么**: 没有单元测试。4 个测试文件全是 subprocess 集成 demo：
- `demo_p2p_secure_loopback.py` — 用 `time.sleep()` 同步，无断言
- `demo_filetransfer.py` — 有 MD5 校验，但仍用 sleep 同步
- `demo_groups_6users.py` — 最好的一个，有 PASS/FAIL，但 0.5s timeout 验证"未收到"不可靠
- `auto_test_requirements.py` — 环境诊断脚本，不是测试

`crypto.py` 的加解密、`session.py` 的状态机转换、`protocol.py` 的边界解析——全部零覆盖。

**对 PQNodium 的启示**:
- 每个模块的 conformance test 是**该模块的第一个交付物**
- 先写 trait + 测试向量，再写 adapter 实现（TDD）
- `crypto/traits` + `crypto/conformance` 应该是 Phase 1 的第一个 PR
- 握手状态机的每个状态转换都要有测试（ZFeiQ 的并发 KX1 竞争就是靠 sleep 3 秒"测试"的）
- CI gate: clippy + test + audit 全通过才能合并

---

### 教训 7：密钥管理粗糙

**发生了什么**:
- 私钥以裸 bytes 写入 `identity.bin`，无加密、无权限控制
- `crypto.py` 返回普通 Python bytes，GC 前一直留在内存
- 没有密钥轮换机制

**对 PQNodium 的启示**:
- 密钥持久化时加密存储（设备级密钥或用户 passphrase 派生）
- 内存中的密钥用 `zeroize` trait 清理，用 `mlock` 防止 swap 到磁盘
- 这应该作为 Phase 1 的硬性要求，不推迟到后续 phase

---

### 教训 8：文件传输开了后窗

**发生了什么**: 消息用 ChaCha20-Poly1305 加密了，但文件走的是**裸 TCP**。文件传输路径没有经过加密通道。等于锁了前门开了后窗。同时文件服务器没有路径验证，存在目录遍历风险。

**对 PQNodium 的启示**: PQNodium 基于 QUIC 传输，TLS 1.3 内置，所有数据流（包括文件）都经过传输层加密。这一点架构设计已经覆盖。但要注意：实现时确保文件流走的也是 QUIC stream，不要单独开裸 TCP 通道。

---

## 三、ZFeiQ vs PQNodium 对比总结

| 维度 | ZFeiQ 的问题 | PQNodium 的应对 |
|------|------------|----------------|
| 身份认证 | 生成密钥但从未使用 | Ed25519 + ML-DSA 混合签名，Phase 1 硬约束 |
| 架构 | God Object 925 行，跨层访问私有方法 | Crate 级隔离 + `pub` 可见性强制边界 |
| 错误处理 | `except: pass` ×14+ | `Result<T, E>` + 编译期强制 |
| 线程安全 | `PendingAck` 无锁数据竞争 | Rust 所有权系统编译期阻止 |
| 测试 | 零单元测试，subprocess demo | conformance test 作为首个交付物，CI gate |
| 密钥管理 | 裸文件存储，无 zeroize | 加密持久化 + zeroize + mlock |
| 文件传输 | 裸 TCP | QUIC + TLS 1.3，无明文通道 |
| 开发节奏 | 一天堆核心，40 天赶完 | 小任务迭代，每个 phase 有 buffer |
| 密码学 | X25519 单层，无后量子 | X25519 + ML-KEM-768 hybrid，可插拔后端 |
| 降级保护 | 无 | 零降级策略：加密不可用则拒绝通信 |

---

## 四、给 PQNodium 开发路线的具体调整建议

| 原计划 | 调整建议 | 理由 |
|--------|---------|------|
| Phase 0：纯文档 | 结束前增加**技术验证 spike** | ZFeiQ 因未验证架构可行性而中途重写 |
| Phase 1：核心加密 | **先交付 trait + conformance test**，再写 adapter | ZFeiQ 零测试导致无法验证加密正确性 |
| Phase 1：无明确约束 | 身份签名和密钥交换**同步实现**，不允许"只加密不认证"的中间态 | ZFeiQ 的认证永远停留在了"必做"清单上 |
| Phase 1：密钥管理未明确 | 加入密钥安全存储（加密持久化 + zeroize + mlock） | ZFeiQ 裸存储密钥，安全隐患 |
| 各 Phase：无 CI 约束 | CI gate: clippy + test + audit 全通过才能合并 | ZFeiQ 的 linter 报错是单独修的 commit，说明没有自动化门禁 |
| Phase 3b：Tauri 壳 | IPC 层只通过 `pqnodium-p2p` 公共 API，Rust `pub` 强制 | ZFeiQ 的 bridge 直接访问私有方法，重构就崩 |
