# 0.1.0 验证记录

## 已完成的本地验证

| 范围 | 结果 |
| --- | --- |
| Rust 密码库核心 | 14 项测试通过：错误主密码、加密篡改、重启、锁定、准确 hostname、授权撤销、最新修改合并、删除、乱序与重复、容量与持久化失败回滚 |
| Rust 网络服务 | 10 项测试通过：真实 HTTP 双库配对及同步、锁定、撤销竞态、Host/Origin/令牌、AEAD/重放/epoch、容量回滚、立即退出及慢请求退出 |
| 插件逻辑 | 13 项 Node 测试通过：准确网站匹配、授权存储、POST 查询契约、请求约束、流式长度限制、HTTPS 填充、防跳转与最小权限 |
| 共享界面 | 11 项浏览器场景通过：创建/解锁、CRUD、授权、锁定清理、过期异步回复、远端记录刷新、手机布局与服务失败时本地可用 |
| Linux 原生客户端 | Release 构建及 DEB 打包通过；实际 WebKit/Tauri 窗口首次建库、保存、锁定、解锁与退出重启后恢复通过 |

原生验证使用独立的应用数据目录和虚构 `.invalid` 测试凭据，未连接真实用户设备。检查了实际密码库文件的 `0600` 权限与加密 envelope，确认不含测试主密码、账号、密码或 hostname 明文。应用 stdout/stderr 为空。

![Linux 原生窗口，重启解锁后的虚构测试条目](desktop/docs/previews/native-vault.png)

共享界面测试使用模拟 IPC，不能代替原生验证；核心和网络测试使用临时目录与本机独立节点，不能代替手机与电脑之间的真实局域网验证。

## 跨平台构建

由 [Build and verify](https://github.com/ecojust/OhMyPassword/actions/workflows/build.yml) 并行验证 Windows x64、macOS ARM64、Linux x64、Android ARM64 和 iOS ARM64 Simulator。整轮验证还包括真实浏览器扩展加载、Origin 和填充测试。

本机 Chromium 的管理员策略禁止加载未打包扩展，因此未改动策略，也未用模拟 Origin 请求冒充真实插件测试；真实扩展结果以 CI 为准。

## 尚需真实设备验证

- Android 与 iOS 的局域网权限、NSD/Bonjour 发现、后台锁定与前台恢复。
- 不同路由器、访客网络隔离、防火墙和断网重连下的跨设备同步。
- 手机系统剪贴板行为，以及 Windows/macOS 的首次安装体验。
- 密码管理器的独立安全审计。

Android CI 包使用开发签名，iOS CI 包供模拟器使用；iPhone 真机安装需开发者签名。macOS 使用 ad-hoc 签名，尚未 Apple 公证。编译、功能测试与代码审阅不等于上述平台许可或完整安全审计。
