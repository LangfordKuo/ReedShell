# ReedShell

使用 Rust 开发的多平台 SSH 工具，支持 Windows、macOS、Android、iOS，以及网页管理端。

- 桌面端：Rust + Iced + iced-fluent-theme
- 移动端：Rust + Slint
- 服务端：Rust + Axum + MySQL + Redis
- 管理端：React + shadcn/ui
- 同步：端到端加密，服务端不持有解密密钥

## 状态

规范制定阶段（M0），尚未开始编码。

| 文档 | 说明 |
|---|---|
| [产品规格](docs/01-产品规格.md) | 功能清单、免费/付费边界、平台矩阵 |
| [架构设计](docs/02-架构设计.md) | 技术选型、模块划分、关键流程 |
| [安全与同步协议](docs/03-安全与同步协议.md) | 密钥体系、E2EE、同步协议、数据表 |
| [交互与 UI 规范](docs/04-交互与UI规范.md) | 界面布局、设计令牌、快捷键 |
| [研发计划](docs/05-研发计划.md) | 里程碑、工程规范、测试与 CI |

## 许可证

本项目采用 **AGPL-3.0 + 商业双许可**：

- 开源使用：遵循 [GNU Affero General Public License v3.0](LICENSE)。
- 闭源分发、应用商店上架、嵌入商业产品：需获得商业许可，见 [LICENSING.md](LICENSING.md)。

外部贡献需签署 CLA，以保留双许可能力。
