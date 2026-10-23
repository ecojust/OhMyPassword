# OhMyPassword

本地密码管理器，包含浏览器插件、桌面客户端和 Android / iOS 客户端。密码在设备上加密保存，已配对的设备通过局域网自动同步，不依赖云端密码服务器。

当前为 **0.1.0 开发版**。首次配对需要用户确认，之后自动同步；修改密码采用**最后修改优先**，收到同步数据时保留原修改时间。请先使用测试凭据验证自己的设备环境，保留现有密码库备份。

## 三个软件目录

| 目录 | 软件与平台 | 负责什么 |
| --- | --- | --- |
| [`extension/`](extension/) | Chrome / Edge 浏览器插件 | 连接本机客户端；按当前网站准确 hostname 查找账号；用户选择后填充；确认保存新增或修改的账号密码 |
| [`desktop/`](desktop/) | Windows / macOS / Linux 客户端 | 创建与解锁加密密码库、管理账号、授权插件、本地 HTTP 接口、设备配对、自动发现与同步 |
| [`mobile/`](mobile/) | Android / iOS 客户端 | 与桌面端共用密码库和管理界面；前台解锁时提供服务、发现设备与同步；回到前台后补同步 |

桌面与移动端共用 `desktop/core/` 的加密与版本合并、`desktop/service/` 的接口与同步协议，以及 `desktop/src/` 的界面。`mobile/` 提供独立手机构建入口和 Android NSD / iOS Bonjour 适配；三个目录属于同一工作区，请克隆完整仓库。

![桌面密码库界面（模拟测试数据）](desktop/docs/previews/desktop-vault.png)

[手机设备同步界面预览（模拟测试数据）](mobile/docs/previews/mobile-devices.png)

## 使用流程

1. 在客户端创建密码库，设置主密码和设备名称。主密码只用于本机解锁；另一设备可以使用不同主密码。
2. 添加网站 hostname、账号与密码。列表默认不展示密码，需要时再显示或复制。
3. 在另一台设备安装并创建自己的密码库。两台设备连接到可互通的局域网，打开并解锁客户端。
4. 一台设备生成限时、单次配对邀请，在另一台设备输入邀请。之后由客户端自动寻找已配对设备并同步。
5. 安装浏览器插件，将插件显示的完整扩展标识复制到客户端授权页面，生成连接令牌，再填入插件。之后点击插件即可查看当前网站匹配的账号并选择填充。
6. 在插件中确认保存新凭据或修改密码后，本机客户端先加密落盘，再触发设备同步。对端离线时等待重连。

浏览器插件不自动提交登录表单，不静默收集所有网站的密码，也不把密码库保存在浏览器存储中。首版没有移动系统自动填充扩展；手机其他 App 的自动填充需后续接入 Android Autofill / iOS Credential Provider。

## 同步规则

- **最新修改为准**：同一条记录的新版本自动覆盖旧版本；相同修改时间通过计数和设备 ID 确定一致顺序，无需用户选取冲突版本。
- **接收时间不是修改时间**：同步不会让旧记录变成“新修改”，乱序或重复收到数据也不会倒退。
- **删除也有版本**：保留删除标记，避免离线设备带回旧记录。历史修订作为恢复参考，删除不等于立刻擦除全部历史副本。
- **发现不等于授权**：只有完成配对的设备才能交换数据。撤销设备会停止后续访问，但无法收回其之前取得的副本。
- **注意设备时钟**：离线场景没有统一服务器时间，请开启系统自动校时。已收到的版本会参与本地版本时钟，严重错误的设备时钟仍不能代表真实操作顺序。

首版的全部记录、历史及删除标记合计最多 **1 MiB 序列化数据**，超限会明确拒绝保存或合并，不会先报告成功再丢弃数据。当前没有历史清理或附件功能。

## 服务与手机后台限制

| 通道 | 默认端口 | 用途 |
| --- | --- | --- |
| `127.0.0.1` HTTP | `17841` | 仅本机插件，校验连接令牌及准确扩展来源 |
| 局域网 HTTP | `17842` | 配对与认证加密同步，不通过 HTTP 明文传输密码 |
| mDNS / Bonjour | 系统服务发现 | 寻找 `_ohmypassword._tcp.`，不广播凭据或密钥 |

电脑客户端运行且密码库解锁时提供服务。手机在前台解锁时运行，进入后台后按生命周期暂停或锁定，返回前台解锁后补同步。普通 iOS 密码管理器无法常驻 HTTP 服务；换成 WebSocket 或 TCP 同样受系统限制。本项目不利用音频、定位等无关权限维持后台运行。

密码库锁定后，插件读取和需要解密的同步停止。Wi-Fi 客户端隔离、防火墙、局域网权限拒绝或跨子网可能影响发现与连接；配对仍保留明确地址的方式，不扫描所有 IP。

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

手机构建步骤与必要配置见 [`mobile/`](mobile/)。Android 开发签名包可以安装测试；iOS 模拟器构建无需分发证书，真机安装与分发需自己的 Apple 签名。构建结果见 [GitHub Actions](https://github.com/ecojust/OhMyPassword/actions)，实际安装包大小以构建产物为准，不把前端资源大小作为软件整体大小。

核心与服务测试：

```sh
npm run test:core
npm run test:service
```

加密、授权、同步与平台边界详见 [架构说明](ARCHITECTURE.md) 和 [安全说明](SECURITY.md)。
