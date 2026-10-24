# OhMyPassword 浏览器扩展

Chrome / Edge 的 Manifest V3 扩展，用于连接**当前电脑**上已解锁的 OhMyPassword 客户端。按当前网站的精确 hostname 查找账号，点击后填充主页面的登录表单，也可明确确认后保存或修改账号。密码更新保留原记录 ID，先保存到本机；其他设备通过客户端中的手动合并取得修改。

## 构建与安装

在仓库根目录执行：

```sh
npm ci
npm run build --workspace @ohmypassword/extension
npm run test:extension
```

产物为 `extension/dist/` 和 `extension/ohmypassword-extension-0.1.0.zip`。Chrome 进入 `chrome://extensions`，Edge 进入 `edge://extensions`，开启开发者模式，选择「加载已解压的扩展程序」并选中 `dist` 目录；ZIP 需先解压。受组织管理且禁止自行安装扩展的浏览器需要管理员分发，不能通过本项目绕过其策略。

当前提供并验证 Chromium MV3 构建，不包含 Safari 扩展；Firefox 的扩展 ID、后台脚本和审核要求不同，尚未提供可发布的 Firefox 包。

## 使用

1. 打开、创建或解锁本机 OhMyPassword 密码库。
2. 打开登录网页，点击扩展，选择对应账号「填入此页面」。扩展默认连接 `http://127.0.0.1:17841`，无需令牌或单独授权设置，也不会自动提交登录表单。
3. 只有客户端使用其他端口时，才需要在「连接设置」修改端口；这里也可以检查连接或恢复默认端口。

本版使用本地接口协议 2，客户端和扩展需同时更新。扩展升级或下次打开时，会从浏览器存储中移除旧版连接令牌和授权元数据，保留有效的自定义端口；无效的旧端口会恢复为 17841。

当前解压加载版本的 Chrome / Edge 扩展 ID 固定为 `abnlejagphkafpbidkngaemnlfgbpdmb`，对应 Origin 为 `chrome-extension://abnlejagphkafpbidkngaemnlfgbpdmb`。Manifest 中的 RSA 公钥用于保持这个 ID 稳定，不是需要用户保存的连接密钥，也不是 CRX 签名私钥。客户端默认只接受这个固定扩展 Origin 的浏览器密码请求，普通网页默认拒绝。

Origin 检查限制浏览器来源，**不能验证本机原生进程的身份**；本机程序能够构造 HTTP 请求头。免令牌接口不提供对本机不可信程序的身份认证，密码库锁定后仍拒绝读取与修改。

添加账号时填写当前网站的账号密码并确认保存。修改已有账号时点击「修改」，保存会更新原记录，不创建另一条记录。扩展不监听键盘、不拦截表单提交，也不自动采集或上传网页里输入的密码。

## 范围

- `example.com` 与 `login.example.com` 分别匹配，不自动跨子域共用密码。
- 凭据查询统一使用 `POST /v1/credentials/search`，JSON 请求体为 `{ "hostname": "example.com" }`；hostname 不放进 URL。连接、查询和保存由浏览器自身发送 Origin，不携带 Authorization 或连接令牌。
- 自动填充要求 HTTPS，避免将同 hostname 的密码填入可被网络篡改的 HTTP 页面；仅本机回环地址作为开发例外。HTTP 网站仍可管理记录，需切到 HTTPS 后填充。
- 只在用户点击后向主框架填充；不填 iframe，不填标注为 `new-password` 的注册密码框。出现多个登录密码框时停止，避免填错表单。
- 注入前再次校验页面的 hostname、origin 和标签 ID，跳转后要求重新打开扩展。
- 本机密码库锁定或客户端未运行时，扩展不会返回缓存密码。每次填充前重新读取当前记录。
- 只保存本地端口，不将账号密码放入浏览器持久存储。使用后可以在客户端锁定密码库。
- 仅申请 `activeTab`、`scripting`、`storage` 与回环地址访问权限，没有全站后台访问权限。
- 网页与扩展 UI 都是原生 JavaScript/CSS，不包含前端框架、远程脚本或分析统计。

## 验证

`npm test --workspace @ohmypassword/extension` 检查默认连接、旧令牌迁移清理、无认证请求、固定扩展 ID 与客户端 Origin 一致、hostname 边界、固定回环目标、禁止重定向、错误提示、存储范围、填充前的跳转检查和最小权限。

真实浏览器检查：

```sh
npx playwright install chromium
npm run test:browser --workspace @ohmypassword/extension
```

此检查加载真实扩展，验证固定 ID、无需令牌的连接与查询、旧令牌迁移清理、POST 实际发送的固定 Origin、hostname 不出现在 URL、原生脚本注入、主框架限制、跳转拒绝、账号更新及锁定处理。它使用合成测试账号和临时本地服务，不读写真实密码库；真实客户端接口的加密、访问限制和同步另由 Rust service 测试覆盖。
