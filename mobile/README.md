# OhMyPassword 移动端

Android 和 iOS 原生客户端，共用桌面端 Rust 加密密码库、同步服务及轻量前端。创建主密码后可新增、编辑、查看、复制和删除密码；密码默认隐藏。局域网设备首次通过一次性邀请配对，之后在应用前台、密码库解锁时自动发现和双向同步，同一条密码使用最新修改，历史版本可供查看。

![移动端设备页面（模拟数据，浏览器布局验证）](docs/previews/mobile-devices.png)

## 运行边界

- **Android 7.0 / API 24+、iOS 15+**。Android 使用 NSD；iOS 使用 Bonjour，首次需要允许本地网络权限。发现服务类型为 `_ohmypassword._tcp.`，只广播协议版本和设备标识，不广播用户填写的设备名称、密码或配对密钥。
- 进入后台立即锁定密码库、停止发现并拒绝密码 API；回到前台后需要重新解锁。解锁后自动补同步。不会申请音频、定位、VPN等无关后台权限，也不承诺后台常驻 HTTP。
- 初次邀请使用本机 IPv4 局域网地址。设备必须网络互通；访客网络隔离、防火墙或拒绝本地网络权限可能阻止同步。配对后会保留端点作为发现失败时的连接方式。
- Android 禁止系统备份并应用 `FLAG_SECURE`；iOS 在切到后台时遮盖应用预览。iOS 本地文件仍受系统备份策略影响，密码库文件自身始终加密。
- 首版未接入 Android Autofill / iOS Credential Provider，手机密码可在客户端查看和手动复制。复制内容会进入系统剪贴板，请留意其他应用的剪贴板权限。
- 手机端与桌面端之间同步凭据，不同步本机主密码、浏览器授权令牌或设备配对权限。每台设备可以使用不同主密码。

## 构建

从仓库根目录先运行 `npm ci`。Android 需要 JDK 17、Android SDK 36、NDK 27.2.12479018、Rust stable 和对应目标；iOS 必须在 macOS 安装 Xcode / Command Line Tools、Rust及 iOS 目标。

```bash
# 在仓库根目录
npm run android:init --workspace @ohmypassword/mobile
npm run android:dev --workspace @ohmypassword/mobile
npm run android:build --workspace @ohmypassword/mobile

# macOS 上运行；模拟器不需要开发者签名
npm run ios:init --workspace @ohmypassword/mobile
npm run tauri --workspace @ohmypassword/mobile -- ios build --ci --debug --target aarch64-sim --no-sign
```

`android:init` / `ios:init` 会调用 Tauri 生成平台工程，然后运行 `.github/scripts/prepare-mobile.py`：Android 固定 SDK 36，关闭系统备份和 WebView 明文网络；iOS 检查本地网络用途说明和 Bonjour 声明。生成工程位于 `src-tauri/gen/`，不作为手写代码维护。iOS 真机安装及分发需要用户自己的 Apple 开发者签名，CI 模拟器 `.app` 不能直接安装到 iPhone。

CI 的 Android 开发包会对 Rust 启用体积优化并移除调试信息，保留开发签名。本地默认调试构建包含调试信息，体积较大；复现 CI 小包的环境变量与命令见 [构建脚本说明](../.github/scripts/README.md)。

主要代码：`src-tauri/` 是移动入口，`plugins/discovery/` 是 Android NSD / iOS Bonjour 及后台预览保护；共享界面在 `../desktop/src/`，加密核心和 HTTP 同步服务在 `../desktop/core/`、`../desktop/service/`。

## 验证

共享核心、双节点 HTTP 同步和前端交互由自动化测试覆盖；移动端原生编译由仓库 CI 检查。实际 Android / iOS 局域网发现、后台切换及跨设备同步仍需要真机验证，编译通过不等于这些行为已实测。
