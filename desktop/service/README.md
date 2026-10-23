# OhMyPassword 本地服务与局域网同步

供桌面端和移动端共用的 Rust 库。它不持有独立明文密码库：所有读写通过 `Arc<Mutex<ohmypassword_core::Vault>>`，服务与密码库均允许访问时才返回密码或同步。服务没有远程解锁接口。

## 浏览器接口

默认只监听 `127.0.0.1:17841`。用户先在客户端填写插件显示的完整 Origin（`chrome-extension://…` 或 `moz-extension://…`），生成专用授权 token，再粘贴到插件。网络接口不能创建或扩大授权。

| 接口 | 请求 | 响应 |
| --- | --- | --- |
| `GET /v1/status` | 无凭据 | `{protocol:1, initialized, locked}`，不含库内容或设备信息 |
| `POST /v1/browser/connect` | `Authorization: Bearer …` | `{connected:true, protocol:1}` |
| `GET /v1/credentials?hostname=example.com` | 同上 | `{entries:[…]}`，精确 hostname 匹配 |
| `POST /v1/credentials/search` | 同上，JSON `{hostname}` | 同上，供需要 POST 的扩展环境使用 |
| `POST /v1/credentials` | 同上，JSON `EntryInput` | `{entry:…}`；成功后触发设备同步 |

敏感请求同时检查精确 Host、已授权扩展 Origin 和 token；预检只允许已授权扩展。锁定返回 423、无效 token 返回 401、来源/Host 被拒绝返回 403。锁定时浏览器预检可能无法读取 423；插件可使用公开状态接口区分“需要解锁”和“服务未运行”。所有响应禁止缓存。Origin 检查用于隔离网页；拥有本机进程权限的恶意软件不在这一接口隔离边界内。

## 设备配对与同步

- LAN 默认端口 `17842`，首版仅支持 IPv4 私网、回环和链路本地地址。只接受数字 IP，不解析 URL 主机名、不跟随重定向，也不使用系统代理。
- `Service::create_invitation(ip)` 生成 `omp1.…` 邀请，含 256 位随机密钥，五分钟有效、一次成功配对后失效。用户将完整邀请交给另一设备；发现广播中不包含邀请或密码。
- 邀请接收端先取得 `GET /v1/challenge` 的当前服务 epoch，再发送 AES-256-GCM 加密的 `POST /v1/pair`。服务器落盘配对后才消耗邀请。双方使用 HKDF-SHA256 派生独立同步密钥，将它保存在各自加密密码库中。两台设备可以使用不同主密码。
- `POST /v1/sync` 的请求与响应均为 AES-256-GCM 密文，AAD 绑定协议版本、方向、路由、双方设备 ID、随机请求 ID 和 epoch。接收方检查消息时间及重放缓存；重启/暂停后 epoch 变化，旧录制消息失效。响应绑定原请求，不能替换为其他请求的回复。
- 同步双方交换记录及删除标记。记录修改时间、稳定版本和最新优先规则由核心库处理；接收同步不刷新修改时间。过期数据不会使已删除记录复活。每次导出、发送前和保存响应前重新验证设备授权；撤销后不再为旧工作队列导出新密码。
- 核心限制序列化记录及历史合计 1 MiB，HTTP 消息上限 2 MiB（包含加密/Base64 开销）。两端合并后超过容量时返回 413 并保留原数据，不执行部分覆盖。一次最多处理 8 个并行 HTTP 请求，LAN 每个源地址每分钟最多 64 个请求。网络请求有超时；这不是完整的 TCP 层抗拒绝服务保证。

桌面使用 mDNS-SD 服务 `_ohmypassword._tcp.local.`，TXT 为 `protocol=1` 和 `device_id`。Android/iOS 使用原生 NSD/Bonjour 适配器，将结果传给 `discovered_peer`；Rust 移动构建不直接发送 mDNS 多播。发现只提供候选地址，不能授予信任；只有通过加密认证的新地址才会持久化。未知设备广播不触发全库同步。

默认每 30 秒尝试同步已配对设备，修改和已配对设备地址变化会触发同步，重复触发合并到至多每两秒一轮。mDNS 不可达时仍尝试上次已认证地址。手机暂停/锁定时停止敏感服务，回到前台并解锁后恢复；不承诺手机后台常驻。不同网段、客户端隔离或防火墙可能阻止直连。

## 验证

```sh
cargo test --locked --manifest-path desktop/service/Cargo.toml
```

测试使用真实本机 HTTP 套接字及独立加密密码库，覆盖授权/Host/Origin、加密篡改、重放、服务 epoch、配对、最新密码和删除同步、容量失败不部分写入、撤销后的旧工作队列、发现不授信及有限时间退出。测试不代表已验证真实手机或所有局域网环境。
