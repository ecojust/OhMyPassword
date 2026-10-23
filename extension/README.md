# OhMyPassword 浏览器扩展

Chrome / Edge 的 Manifest V3 扩展，用于连接**当前电脑**上已解锁的 OhMyPassword 客户端。按当前网站的精确 hostname 查找账号，点击后填充主页面的登录表单，也可明确确认后保存或修改账号。密码更新保留原记录 ID，由客户端同步到已配对设备。

## 构建与安装

在仓库根目录执行：

```sh
npm ci
npm run build --workspace @ohmypassword/extension
npm run test:extension
```

产物为 `extension/dist/` 和 `extension/ohmypassword-extension-0.1.0.zip`。Chrome 进入 `chrome://extensions`，Edge 进入 `edge://extensions`，开启开发者模式，选择「加载已解压的扩展程序」并选中 `dist` 目录；ZIP 需先解压。受组织管理且禁止自行安装扩展的浏览器需要管理员分发，不能通过本项目绕过其策略。

当前提供并验证 Chromium MV3 构建，不包含 Safari 扩展；Firefox 的扩展 ID、后台脚本和审核要求不同，尚未提供可发布的 Firefox 包。

## 首次连接

1. 打开、创建或解锁本机 OhMyPassword 密码库。
2. 在扩展的「连接设置」复制完整扩展标识，例如 `chrome-extension://…`。
3. 在客户端「浏览器授权」添加此标识，复制生成的一次性展示令牌。
4. 将令牌粘贴到扩展，点击「验证并连接」。默认连接 `http://127.0.0.1:17841`；只有客户端端口有变化时才需修改。
5. 打开登录网页，点击扩展，选择对应账号「填入此页面」。扩展不会自动提交登录表单。

添加账号时填写当前网站的账号密码并确认保存。修改已有账号时点击「修改」，保存会更新原记录，不创建另一条记录。扩展不监听键盘、不拦截表单提交，也不自动采集或上传网页里输入的密码。

## 范围

- `example.com` 与 `login.example.com` 分别匹配，不自动跨子域共用密码。
- 凭据查询统一使用 `POST /v1/credentials/search`，JSON 请求体为 `{ "hostname": "example.com" }`；hostname 不放进 URL。连接、查询和保存均由浏览器自身发送扩展 Origin，并接受客户端的严格 Origin 与令牌校验。
- 自动填充要求 HTTPS，避免将同 hostname 的密码填入可被网络篡改的 HTTP 页面；仅本机回环地址作为开发例外。HTTP 网站仍可管理记录，需切到 HTTPS 后填充。
- 只在用户点击后向主框架填充；不填 iframe，不填标注为 `new-password` 的注册密码框。出现多个登录密码框时停止，避免填错表单。
- 注入前再次校验页面的 hostname、origin 和标签 ID，跳转后要求重新打开扩展。
- 本机密码库锁定、扩展授权撤销或客户端未运行时，扩展不会返回缓存密码。每次填充前重新读取当前记录。
- 只保存连接令牌和端口，不将账号密码放入浏览器持久存储。清除连接后，还可以在客户端撤销对应授权。
- 仅申请 `activeTab`、`scripting`、`storage` 与回环地址访问权限，没有全站后台访问权限。
- 网页与扩展 UI 都是原生 JavaScript/CSS，不包含前端框架、远程脚本或分析统计。

## 验证

`npm test --workspace @ohmypassword/extension` 检查 hostname 边界、固定回环目标、禁止重定向、错误提示、存储范围、填充前的跳转检查和最小权限。

真实浏览器检查：

```sh
npx playwright install chromium
npm run test:browser --workspace @ohmypassword/extension
```

此检查加载真实扩展，验证连接和凭据查询 POST 实际发送的 Origin、hostname 不出现在 URL、连接设置、原生脚本注入、主框架限制、跳转拒绝、账号更新及锁定处理。它使用合成测试账号和临时本地服务，不读写真实密码库；真实客户端接口的加密、授权和同步另由 Rust service 测试覆盖。
