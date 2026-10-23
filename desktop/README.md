# OhMyPassword 桌面端

基于 Tauri 2、Rust 和原生 TypeScript/CSS 的本地密码管理器，支持 Windows x64、macOS Apple Silicon（macOS 11+）、Linux x64。使用系统 WebView，没有内置 Chromium、Node.js 或远程账户服务。

![密码库界面（模拟数据）](docs/previews/desktop-vault.png)

## 使用

1. 首次打开设置设备名称和至少 10 个字符的主密码。主密码无法找回；设备数据以 Argon2id 派生密钥、AES-256-GCM 加密保存在应用数据目录中。
2. 在「密码库」新增网站 hostname、账号和密码，点击条目编辑。默认隐藏密码，只有明确点击显示/复制才展示或复制。保存后自动同步在线、已配对且已解锁的设备。
3. 在「设备同步」输入本机局域网 IPv4（会自动列出已知网卡地址），生成 5 分钟一次性邀请，在另一台设备中粘贴配对。配对成功后通过 mDNS 自动发现和定时同步；同一条密码以最新修改为准，旧版本可在「历史版本」查看。
4. 在浏览器插件复制扩展标识，在本客户端「浏览器连接」粘贴并生成连接令牌，再把令牌粘贴回插件。每个授权精确绑定扩展 Origin，可随时撤销。
5. 手动锁定或 15 分钟无应用内操作后，密码 API 和同步暂停；解锁后恢复。桌面失去焦点不会锁定，方便浏览器插件使用；关闭窗口会退出进程，最小化仍运行。首版没有托盘及开机自启。

局域网解除配对只阻止与本机后续同步，不会远程擦除其他设备已经持有的数据。复制密码后内容仍在系统剪贴板中。浏览器预览不保存密码，只有原生客户端提供密码库操作。

## 开发与构建

先安装 Node.js 22+、Rust stable，以及对应平台的 [Tauri 系统依赖](https://v2.tauri.app/start/prerequisites/)。Linux 需要 GTK3 / WebKitGTK 4.1；Windows 使用 WebView2。

```bash
# 仓库根目录
npm ci
npm run build --workspace @ohmypassword/desktop
npm run tauri --workspace @ohmypassword/desktop -- dev
npm run tauri --workspace @ohmypassword/desktop -- build
```

`src/` 是与移动端共用的前端，`src-tauri/` 是原生壳与窄范围 IPC；`core/` 负责加密存储，`service/` 负责本机 HTTP 接口、配对和加密同步。构建只把编译后的资源嵌入应用，开发依赖不会打入安装包。Release 开启体积优化、LTO 和符号移除。

本地密码 HTTP 默认只监听 `127.0.0.1:17841`，局域网加密同步端口为 `17842`。客户端不会提供未授权的网络创建授权令牌接口，不会把 Peer 密钥返回给 WebView。端口被占用时密码库仍可本地使用，网络功能会显示错误。

自动化测试覆盖密码库与 HTTP 同步、浏览器插件和 UI；真机联网及各系统生命周期验证以根目录验证记录为准。macOS 构建使用 ad-hoc 签名，不代表 Developer ID 签名或 Apple 公证。
