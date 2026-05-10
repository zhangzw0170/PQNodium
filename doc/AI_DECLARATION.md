# AI 辅助开发声明 / AI-Assisted Development Declaration

本项目在开发、设计、仿真和验证过程中使用了人工智能辅助工具。所有代码和文档最终均由人类开发者审查并确认。

This project uses AI-assisted tools during development, design, simulation, and verification. All code and documentation are ultimately reviewed and approved by human developers.

## 使用的 AI 工具 / AI Tools Used

| 工具 / Tool | 用途 / Usage |
|-------------|-------------|
| **Claude Code** (Anthropic) | 核心代码生成、架构设计、安全审计建议<br>Core code generation, architecture design, security audit suggestions |
| **OpenCode** | 交互式开发辅助、代码重构、文档编写<br>Interactive development assistance, code refactoring, documentation |
| **GLM 5 Turbo / GLM 5.1** (智谱 AI / Zhipu AI) | 中文文档撰写、国密算法调研、创意头脑风暴<br>Chinese documentation, SM crypto research, creative brainstorming |

## 安全原则 / Security Principles

- **Human-in-the-Loop**: AI 生成内容必须经过人类逻辑审查和验证。<br>AI-generated content must undergo human logical review and verification.
- **加密算法独立验证**: 所有加密实现均经过独立测试，未直接采纳未经验证的 AI 代码。<br>All cryptographic implementations are independently tested; unverified AI code is never adopted directly.
- **透明度**: 本项目公开 AI 使用情况，鼓励外部审计者关注 AI 可能引入的盲点。<br>We disclose AI usage to encourage external auditors to watch for AI-introduced blind spots.

## AI 工具的局限性 / Limitations of AI Tools

- AI 可能在加密实现中引入**侧信道漏洞** (Side-channel vulnerabilities)。
- AI 生成的代码可能在**极端边界条件**下行为不可预测。
- AI 不具备**法律合规**判断能力，国密算法的使用需符合当地法规。

---

*最后更新 / Last updated: 2026-05-06*
