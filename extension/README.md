# OhMyPassword 浏览器扩展

Chrome / Edge 的 Manifest V3 扩展，用于连接**当前电脑**上首次解锁且仍在运行的 OhMyPassword 客户端；锁定客户端界面后插件仍可使用。按当前网站的可注册主域名查找账号，点击后填充登录表单，也可确认后保存或修改账号。支持主页面、能唯一确认的同源登录 iframe，以及经过单独授权的 Apple、网易登录 iframe。密码更新保留原记录 ID，先保存到本机；其他设备通过客户端中的手动合并取得修改。

## 构建与安装

在仓库根目录执行：

```sh
npm ci
npm run build --workspace @ohmypassword/extension
npm run test:extension
```

需要 Node.js 22 或更新版本。当前 0.2.5 的产物为 `extension/dist/` 和 `extension/ohmypassword-extension-0.2.5.zip`。Chrome 进入 `chrome://extensions`，Edge 进入 `edge://extensions`，开启开发者模式，选择「加载已解压的扩展程序」并选中 `dist` 目录；ZIP 需先解压。受组织管理且禁止自行安装扩展的浏览器需要管理员分发，不能通过本项目绕过其策略。

当前提供并验证 Chromium MV3 构建，不包含 Safari 扩展；Firefox 的扩展 ID、后台脚本和审核要求不同，尚未提供可发布的 Firefox 包。

## 使用

1. 打开、创建或首次解锁本机 OhMyPassword 密码库。0.2.5 客户端手动或自动锁定界面后，插件仍可使用；完全锁定、退出或重启后需重新解锁。
2. 打开登录网页，必要时手动切换到账号密码登录，等待表单加载，再点击扩展并选择对应账号「填入此页面」。扩展默认连接 `http://127.0.0.1:17841`，无需连接令牌。
3. 如果当前只有账号输入框，扩展只填账号。请在网页手动点击「下一步」；出现密码步骤后，再次打开扩展并选择账号填充。扩展不会点击下一步或自动提交登录。
4. 遇到 Apple 或网易的内嵌登录框，按下文提示单独授权，再次选择账号。验证码、短信动态码、验证器代码、扫码和 Passkey 由你与网站完成，扩展不会代填或操作。
5. 只有客户端使用其他端口时，才需要在「连接设置」修改端口；这里也可以检查连接或恢复默认端口。

本版继续使用本地浏览器接口协议 2；客户端 0.2.3 起的局域网接收另用协议 3，两者独立。建议客户端和扩展使用配套版本。扩展升级或下次打开时，会从浏览器存储中移除旧版连接令牌和授权元数据，保留有效的自定义端口；无效的旧端口会恢复为 17841。

当前解压加载版本的 Chrome / Edge 扩展 ID 固定为 `abnlejagphkafpbidkngaemnlfgbpdmb`，对应 Origin 为 `chrome-extension://abnlejagphkafpbidkngaemnlfgbpdmb`。Manifest 中的 RSA 公钥用于保持这个 ID 稳定，不是需要用户保存的连接密钥，也不是 CRX 签名私钥。客户端默认只接受这个固定扩展 Origin 的浏览器密码请求，普通网页默认拒绝。

Origin 检查限制浏览器来源，**不能验证本机原生进程的身份**；本机程序能够构造 HTTP 请求头。免令牌接口不提供对本机不可信程序的身份认证，客户端完全锁定后拒绝读取与修改；界面锁定期间允许本机插件继续读写。

添加账号时填写当前网站的账号密码并确认保存。修改已有账号时点击「修改」，保存会更新原记录，不创建另一条记录。扩展不监听键盘、不拦截表单提交，也不自动采集或上传网页里输入的密码。

## 常用登录页适配

下表描述 0.2.2 的规则与已观察到的页面结构。2026-10-24 的实站检查只打开公开入口、查看表单或切换登录模式，没有输入或提交真实账号密码，因此不代表已经验证真实账户登录成功。

| 网站 | 当前适配流程 | 实站只读检查范围 |
| --- | --- | --- |
| Apple Account / iCloud | Apple 账号与密码；支持 `idmsa.apple.com` 登录 iframe，需单独授权；明确登录路径可只填账号 | `account.apple.com/sign-in`、iCloud 登录入口及其实际 iframe，观察到账号、密码框 |
| ChatGPT / OpenAI | ChatGPT `/auth/login` 和明确的 OpenAI 登录路径；支持账号第一步，再由用户进入密码步骤 | ChatGPT 邮箱第一步；OpenAI 独立入口返回会话结束，未实查后续密码步骤 |
| Gmail / Google | Gmail 跳转到 `accounts.google.com`，支持账号第一步；忽略隐藏的密码字段 | Google 账号第一步；未提交账号，后续密码步骤未实查 |
| Gitee | 可见账号、密码表单；过滤隐藏短信表单中的重复 ID | `gitee.com/login` 的账号密码表单 |
| 网易 163 邮箱 | `mail.163.com` → `dl.reg.163.com` 的账号密码登录 iframe，需单独授权 | 当前登录 iframe、字段及登录模式标记 |
| 网易 126 邮箱 | `mail.126.com` → `passport.126.com` 的账号密码登录 iframe，需单独授权 | 当前登录 iframe、字段及登录模式标记；与 163 账号保持隔离 |
| GitHub | 账号与当前密码表单；忽略隐藏字段 | `github.com/login` 的账号密码表单 |
| Microsoft 个人账号 | `login.live.com` 的账号第一步；兼容多 token 的 `autocomplete` 属性 | 账号第一步；未实查后续密码、Passkey 或验证码步骤 |
| 百度 | 先手动切换到「用户名登录」，再填账号与密码 | `passport.baidu.com` 的用户名登录模式；不依赖动态生成的完整输入框 ID |
| 哔哩哔哩 | 账号与密码输入框，支持没有 `<form>` 的登录布局 | `passport.bilibili.com/login` 的账号密码字段 |

QQ 邮箱的页面脚本在本次调研环境被网络拦截，未取得有效登录表单证据。本版仅保留通用表单识别，不声明 QQ 专项适配，也没有为其增加跨域 iframe 权限。

只填账号的能力限定在已知登录路径；注册、找回、重置密码和订阅邮箱等流程不会仅因为位于同一个网站就启用。通用识别会过滤隐藏、禁用、只读、验证码及新密码字段。网易实际登录密码框误标为 `new-password`，仅在准确的顶层站点、iframe 地址、产品参数和当前登录模式都符合规则时允许填充，不会全局放开这一限制。

网站会调整路径、DOM 和登录流程，规则需要持续维护。遇到多个候选表单、表单尚未加载、页面跳转或无法确认登录框时，扩展会提示停止填充；可先切换到密码登录、等待加载并重试，或在客户端复制账号密码。

## 内嵌登录框权限

扩展默认只有 `activeTab`、`scripting`、`storage` 和本机回环地址访问权限。跨域登录框只声明以下三个可选来源，不申请全站访问：

| 顶层网站 | 可单独申请的登录框来源 |
| --- | --- |
| `mail.163.com` | `https://dl.reg.163.com/*` |
| `mail.126.com` | `https://passport.126.com/*` |
| `account.apple.com`、`appleid.apple.com`、`icloud.com`、`www.icloud.com` | `https://idmsa.apple.com/*` |

首次填充需要这些权限时，扩展显示独立的「允许访问 … 登录框」按钮。只有点击该按钮才调用浏览器的权限申请；每次只申请当前需要的来源。允许后仍需再次选择账号，不会直接发送密码。拒绝授权后可以稍后再试，或在客户端复制账号密码。

授权不会放开其他顶层站点、来源或端口。跨域组合必须是表中对应的 HTTPS 来源，非默认端口不允许；Apple 的 `apps.apple.com` 退出框、OpenAI 的辅助 iframe、第三方社交登录框不在此名单内。填充只面向能唯一确认的可见直接登录 iframe，并重新检查页面、登录框与目标文档；不会向全部 iframe 广播账号密码。

## 数据与填充范围

- 凭据查询统一使用 `POST /v1/credentials/search`，JSON 请求体为 `{ "hostname": "example.com" }`；hostname 不放进 URL。连接、查询和保存由浏览器自身发送 Origin，不携带 Authorization 或连接令牌。
- 自动填充要求 HTTPS，避免将同主域名的密码填入可被网络篡改的 HTTP 页面；仅本机回环地址作为开发例外。HTTP 网站仍可管理记录，需切到 HTTPS 后填充。
- 只在用户点击后填充，先探测当前步骤，再向选定的文档发送所需账号或密码。注册、改密、OTP 与不明确的表单不作为普通密码登录处理。
- 注入前再次校验页面 URL、hostname、origin、标签 ID 和文档身份；页面或登录框变化后要求重新选择账号。
- 客户端完全锁定或未运行时，扩展不会返回缓存密码。界面锁定期间仍向本机客户端实时查询，不使用缓存副本。每次填充前重新读取当前记录。
- 只保存本地端口，不将账号密码放入浏览器持久存储。需要停止插件时，在客户端选择「完全锁定并停止插件」。
- 扩展 UI 和填充逻辑使用原生 JavaScript/CSS，不包含前端框架、远程脚本或分析统计。

## 主域名匹配

`login.example.com`、`www.example.com` 与 `example.com` 共用匹配范围；`co.uk` 等多级后缀会按正确的可注册主域分组。内置 PSL 的 PRIVATE 规则将不同托管租户隔离，例如 `alice.github.io` 与 `bob.github.io` 不匹配。IP、localhost、未知后缀和公共后缀本身仍精确匹配。

列表显示账号原保存网站；修改已有账号保留原 hostname 和 ID，新账号保存当前完整 hostname。页面跳转检查仍精确比较目标，即使跳转到同主域的另一个子域也要重新选择账号。客户端与扩展应使用配套的 0.2.3 版本。

除主域名匹配外，扩展仅在以下**精确的官方登录入口**添加账号别名查询：

| 当前页面 hostname | 可查询和使用的账号所属主域 |
| --- | --- |
| `accounts.google.com`、`mail.google.com` | `gmail.com`、`google.com` |
| `auth.openai.com`、`auth0.openai.com`、`chatgpt.com`、`chat.openai.com` | `chatgpt.com`、`openai.com` |
| `account.apple.com`、`appleid.apple.com`、`idmsa.apple.com`、`icloud.com`、`www.icloud.com` | `apple.com`、`icloud.com` |

这些是从已保存账号到指定登录入口的单向规则，不会扩展到任意子域或根据页面上的 OAuth 按钮推导新别名。例如在 ChatGPT 点击「使用 Google 登录」后，应在 Google 页面选择 Google 账号，ChatGPT 密码不会因此匹配到 Google。`163.com` 与 `126.com` 始终是不同的账号范围，不因共用登录组件或页面里的预加载 iframe 而互相匹配。

域名解析及规则随插件一起打包，运行时不请求第三方服务；打包只包含用到的解析代码和数据，依赖许可附于 `THIRD-PARTY-LICENSES.txt`。

## 验证

`npm test --workspace @ohmypassword/extension` 检查默认连接、旧令牌清理、免令牌请求、固定扩展 ID 与客户端 Origin 一致、PSL 边界、单向官方别名、登录路径范围、固定回环目标、跳转拒绝、存储范围及权限声明。iframe 的授权状态、文档选择、取消和导航竞争等调度逻辑使用浏览器 API 替身测试。

在真实 Chromium 中运行合成页面和已加载扩展的回归检查：

```sh
npx playwright install chromium
npm run test:login-pages --workspace @ohmypassword/extension
npm run test:browser --workspace @ohmypassword/extension
```

`test:login-pages` 在真实 Chromium 渲染器中运行模拟各类登录页的 DOM，所有页面请求都由本地测试拦截。覆盖账号与密码、分步登录、隐藏字段、重复 ID、无 form、iframe、Shadow DOM、动态重绘、注册与验证码拒绝及不自动提交。这里的 iframe DOM 检查不等于验证浏览器扩展权限弹窗，也不等于成功登录实际网站。

`test:browser` 加载真正的扩展，验证固定 ID、无需令牌的本地连接、旧令牌清理、HTTP 请求实际携带的固定 Origin、hostname 不出现在 URL、脚本注入、跳转拒绝、账号更新及锁定处理。填充检查也确认无关 iframe 不收到密码。它使用虚构账号和临时本地服务，不读写真实密码库；真实客户端的加密、接口访问限制与合并另由 Rust core/service 测试覆盖。

CI 运行上述单元、合成 DOM 与扩展浏览器检查。它们用于防止实现回归；实站只读检查用于更新页面结构依据，两者都不包含真实账号登录、短信验证码或多因素认证的成功验证。
