# OhMyPassword

本地密码管理器，包含浏览器插件、桌面客户端和 Android / iOS 客户端。密码在设备上加密保存，通过局域网检测设备并手动合并密码本，不依赖云端密码服务器。

当前版本为 **0.2.0**：插件免连接令牌，设备免邀请码；每 **5 分钟**自动检测，也可手动检测。用户发起合并、两端确认后才交换密码；两端完成后提示 **“已合并密码本”**。同一条密码继续采用最后修改优先规则。

## 三个软件目录

| 目录 | 软件与平台 | 负责什么 |
| --- | --- | --- |
| [`extension/`](extension/) | Chrome / Edge 浏览器插件 | 连接本机客户端；按当前网站准确 hostname 查找账号；用户选择后填充；确认保存新增或修改的账号密码 |
| [`desktop/`](desktop/) | Windows / macOS / Linux 客户端 | 加密密码库、账号管理、免令牌的本机插件接口、自动/手动检测设备、手动合并密码本 |
| [`mobile/`](mobile/) | Android / iOS 客户端 | 共用密码库和管理界面；前台解锁时检测设备与手动合并，后台锁定，返回前台后恢复检测 |

桌面与移动端共用 `desktop/core/` 的加密与版本合并、`desktop/service/` 的接口与同步协议，以及 `desktop/src/` 的界面。`mobile/` 提供独立手机构建入口和 Android NSD / iOS Bonjour 适配；三个目录属于同一工作区，请克隆完整仓库。

![桌面密码库界面（模拟测试数据）](desktop/docs/previews/desktop-vault.png)

[手机设备同步界面预览（模拟测试数据）](mobile/docs/previews/mobile-devices.png)

## 测试包与大小

安装包与插件见 [GitHub Release v0.2.0](https://github.com/ecojust/OhMyPassword/releases/tag/v0.2.0)，附统一 SHA256 校验文件。下表来自已通过全部检查的实际构建产物，详细验证范围见 [验证记录](VALIDATION.md)。

| 产物 | 平台 | 实际文件大小 |
| --- | --- | ---: |
| 浏览器插件 ZIP | Chrome / Edge | 12.0 KiB |
| 桌面安装器 | Windows x64 | 1.62 MiB |
| 桌面便携 EXE | Windows x64 | 4.45 MiB |
| 桌面 DMG | macOS ARM64 | 2.07 MiB |
| 桌面 DEB | Linux x64 | 2.39 MiB |
| 开发 APK，Rust 代码已优化 | Android ARM64 | 13.56 MiB |
| 模拟器 App ZIP | iOS ARM64 Simulator | 18.99 MiB |

大小按实际下载文件统计。桌面使用系统 WebView：Windows 需要 WebView2，Linux 需要 GTK / WebKitGTK，macOS 使用系统 WebKit；上述体积不包含系统运行时。移动包均供开发测试，Android 使用开发签名，iOS 模拟器包不能直接安装到 iPhone。插件 ZIP 解压后按 [插件说明](extension/README.md) 加载。

## 使用流程

1. 在客户端创建密码库，设置主密码和设备名称。主密码只用于本机解锁；另一设备可以使用不同主密码。
2. 添加网站 hostname、账号与密码。列表默认不展示密码，需要时再显示或复制。
3. 在另一台设备安装并创建自己的密码库。两台设备连接到可互通的局域网，打开并解锁客户端。
4. 打开「设备同步」，等待自动检测或点击「手动检测设备」。选择目标设备并点击「合并密码本」，核对两端显示的会话编号一致，再在两台设备上分别确认。无需复制或输入邀请码。
5. 两端完成保存并确认后显示「已合并密码本」。拒绝、超时、锁定或写入失败会显示对应状态；需要时可重新手动合并。
6. 安装浏览器插件，打开并解锁本机客户端即可使用。默认直接访问 `127.0.0.1:17841`，无需连接令牌或额外授权步骤。
7. 在插件或客户端保存新凭据、修改密码时，只保存到本机；需要其他设备取得修改时，再次发起手动合并。

从 0.1.0 升级时请同时更新客户端和插件。原有加密密码库继续使用；插件会清理旧连接令牌，新流程不使用旧邀请码或长期自动同步权限。协议 2 的设备仅发现与其兼容的设备。

**Android 升级限制：** 0.1.0 与 0.2.0 的开发 APK 签名证书不同，不能直接覆盖安装。不要通过卸载旧应用来升级尚未迁出的唯一密码库：卸载会删除应用数据，且 Android 系统备份已禁用。请保留旧应用和数据，先确认密码已完整保存到其他可访问设备或完成可恢复的备份。桌面端的旧密码库读取已通过实际升级验证。

浏览器插件不自动提交登录表单，不静默收集所有网站的密码，也不把密码库保存在浏览器存储中。首版没有移动系统自动填充扩展；手机其他 App 的自动填充需后续接入 Android Autofill / iOS Credential Provider。

## 合并规则

- **最新修改为准**：同一条记录的新版本自动覆盖旧版本；相同修改时间通过计数和设备 ID 确定一致顺序，无需用户选取冲突版本。
- **接收时间不是修改时间**：同步不会让旧记录变成“新修改”，乱序或重复收到数据也不会倒退。
- **删除也有版本**：保留删除标记，避免离线设备带回旧记录。历史修订作为恢复参考，删除不等于立刻擦除全部历史副本。
- **每次手动确认**：设备检测只更新列表；每次合并需要发起和接受，完成一次不会开启之后的自动同步。对方取得的数据副本无法远程收回。
- **注意设备时钟**：离线场景没有统一服务器时间，请开启系统自动校时。已收到的版本会参与本地版本时钟，严重错误的设备时钟仍不能代表真实操作顺序。

首版的全部记录、历史及删除标记合计最多 **1 MiB 序列化数据**，超限会明确拒绝保存或合并，不会先报告成功再丢弃数据。当前没有历史清理或附件功能。

## 服务与手机后台限制

| 通道 | 默认端口 | 用途 |
| --- | --- | --- |
| `127.0.0.1` HTTP | `17841` | 插件免令牌直连，校验准确扩展来源、Host 和解锁状态 |
| 局域网 HTTP | `17842` | 单次手动合并的加密会话 |
| mDNS / Bonjour | 系统服务发现 | 寻找 `_ohmypassword._tcp.`，不广播凭据或密钥 |

电脑客户端运行且密码库解锁时提供服务。手机在前台解锁时运行，进入后台后按生命周期暂停或锁定，结束尚未完成的合并会话；返回前台解锁后恢复检测。普通 iOS 密码管理器无法常驻 HTTP 服务；换成 WebSocket 或 TCP 同样受系统限制。

密码库锁定后，插件读取和合并停止。Wi-Fi 客户端隔离、防火墙、局域网权限拒绝或跨子网可能影响发现与连接。默认只允许 OhMyPassword 插件的浏览器来源，普通网页不能任意获取密码；免令牌模式无法认证自行构造 HTTP 请求的本机原生程序，解锁期间需要信任本机程序。

首版局域网传输使用 IPv4；自动发现与手机原生适配也选择 IPv4 地址。

## 构建

需要 Node.js 22+、Rust stable，以及 [Tauri 平台开发依赖](https://v2.tauri.app/start/prerequisites/)。Android 另需 JDK / Android SDK / NDK；iOS 构建需 macOS 与 Xcode。

```sh
git clone https://github.com/ecojust/OhMyPassword.git
cd OhMyPassword
npm ci
npm run build
```

桌面开发与打包：

```sh
npm run tauri --workspace @ohmypassword/desktop -- dev
npm run tauri --workspace @ohmypassword/desktop -- build
```

浏览器插件：

```sh
npm run build --workspace @ohmypassword/extension
npm run test:extension
```

手机构建步骤与必要配置见 [`mobile/`](mobile/)。Android 开发签名包可以安装测试；iOS 模拟器构建无需分发证书，真机安装与分发需自己的 Apple 签名。最新构建结果见 [GitHub Actions](https://github.com/ecojust/OhMyPassword/actions)。

核心与服务测试：

```sh
npm run test:core
npm run test:service
```

加密、授权、同步与平台边界详见 [架构说明](ARCHITECTURE.md)、[安全说明](SECURITY.md) 和 [验证记录](VALIDATION.md)。
