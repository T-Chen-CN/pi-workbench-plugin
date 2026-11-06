# pi-workbench（Hermes 插件，独立仓库）

> 仓库根目录**就是插件本体**（`plugin.yaml` 在根）——`hermes plugins install` 只认这种形状。
> 客户端与应用侧文档仍在 Pi Workbench 应用仓库；本仓库只放插件代码、测试与 `plugin.yaml` 版本。

本地 Pi Workbench ↔ 云端 Hermes 的**唯一入口**。它是 Hermes 的 `kind: platform`
插件，跑在 VPS 的 gateway 进程里，负责：

| 能力 | 说明 |
| --- | --- |
| 设备身份 | 每台机器一把 `pi_…` token，服务端只存 sha256；token → `deviceId` 是唯一权威 |
| 权限 | scope：`chat`（对话）/ `dispatch`（派活）/ `admin`（改配置） |
| 反向代理 | 除 dashboard 外所有接口透明转发到 `127.0.0.1:8642`，重写鉴权、注入 `X-Pi-Device`、SSE 不缓冲 |
| 审计 | SQLite + `audit-*.jsonl` 双写（token 与 prompt 永不上日志） |
| 派活（H3） | 工作区级任务邮箱 + `local_workspaces` / `local_devices` / `local_dispatch` / `local_task` |

## 三层结构（改动前先读）

```
plugin.yaml  清单（不要写 capabilities：只接受 Hermes 注册表里的 id）
__init__.py  register(ctx) → 只调 shim
shim.py      唯一碰 Hermes 插件 API 的文件（register_platform + plugin_data_dir）
adapter.py   BasePlatformAdapter 子类：connect() 起服务线程，disconnect() 收
config.py    唯一读环境变量的地方（plugin-owned / host-owned 两张清单）
core/        纯 stdlib，不知道 Hermes 存在 → 能 5 分钟外提成独立服务
```

**硬约束**

- `core/` 不许 `import gateway` / `plugins`；需要的数据（数据目录、上游地址、密钥）由 `shim`/`adapter` 传进来。
- 除 `config.py` 外**不许直接读 `os.environ`**：环境变量的名字、默认值、取值范围只有一处，
  `tests/test_config.py` 会拿它和 `plugin.yaml` 对账（新变量没声明/声明了没读都会红）。
- 传输用 stdlib（`ThreadingHTTPServer` + `http.client`），**不要换成 aiohttp**：
  服务跑在独立线程里，插件崩了打不死 gateway 的事件循环。
- 上游签名变更只允许改 `shim.py` / `adapter.py`；`Platform(...)` 已有兜底（取值 → 属性 → 裸字符串），
  上游把枚举收严时不会连带 gateway 启动失败。
- **故意没有 chat 面**：`send()` 恒返回 `SendResult(success=False)`，不要"补上"它。

## 配置（谁提供哪个变量）

`config.py` 里两张清单就是事实源：

| 变量 | 归属 | 默认值 |
| --- | --- | --- |
| `PI_HUB_ADMIN_KEY` | 插件（`requires_env`，secret） | — 缺了只是不能登记/撤销设备 |
| `HERMES_API_BASE` | 插件（`optional_env`） | `http://127.0.0.1:8642` |
| `PI_HUB_PORT` / `PI_HUB_HOST` | 插件（`optional_env`） | `8484` / `127.0.0.1` |
| `PI_HUB_RATE_LIMIT` | 插件（`optional_env`） | `60` |
| `PI_HUB_DASHBOARD_BASE` | 插件（`optional_env`） | `http://127.0.0.1:9119` |
| `PI_HUB_FS_ROOTS` | 插件（`optional_env`） | 空 = profile 的 upload/cache 目录 |
| `API_SERVER_KEY` / `HERMES_DASHBOARD_SESSION_TOKEN` / `HERMES_HOME` | **Hermes/systemd 提供**，不进 manifest | — |

两条与 Hermes 常规的对账：

- **密钥不落 `.env`**：Hermes 允许 `requires_env` 的值来自 profile `.env`，但那个文件 agent 读得到。
  所以 `PI_HUB_ADMIN_KEY` 写在 gateway 的 systemd drop-in 里（env 优先于 `.env`），manifest 里标 `secret: true`
  保证装的时候输入是掩码的。
- **不声明 `capabilities`**：本插件不用 `tools.override` / `ctx.llm` / `gateway.platform_actions`，
  所以不该出现同意屏；真要用某个特权面向时再补，声明了才有。
- **`provides_tools` 现在为空是对的**：H3 的四个工具落地时必须同时加 `tools.py: register_tools(ctx)`
  和 manifest 里的 `provides_tools` 列表，否则 `hermes plugins validate` 的 declared-tools 检查会红。

## 本地开发

```bash
python -m unittest discover -s tests -t . -v     # 102 个用例，约 20 秒，零依赖
hermes plugins validate .                        # 清单/声明对账（需要装 Hermes）
```

## 部署到 VPS

```bash
# 1) 装插件（profile 级，用不可变 SHA 钉版本；公开仓库，不需要任何凭据）
hermes plugins install https://github.com/T-Chen-CN/pi-workbench-plugin.git --ref <40位SHA>

# 过渡期（尚未切成 git 安装）仍可 rsync 整个目录：
#   rsync -a --delete ./ ubuntu@<服务器地址>:/home/ubuntu/.hermes/profiles/pi-cloud/plugins/pi-workbench/
# 然后 hermes plugins adopt pi-workbench 让它变成 tracked 安装

# 2) 启用（HERMES_HOME 必须指 profile，不是 ~/.hermes）
export HERMES_HOME=/home/ubuntu/.hermes/profiles/pi-cloud
hermes plugins list | grep pi-workbench
hermes plugins enable pi-workbench

# 3) 环境变量进 systemd drop-in（不要写 .env：agent 读得到）
#    PI_HUB_ADMIN_KEY / HERMES_API_BASE=http://127.0.0.1:8642 / PI_HUB_PORT=8484
#    其余可选变量与默认值见上面的「配置」表；写错的值会降级成默认并打 WARNING，不会导致起不来

# 4) 工具白名单（H3 起需要；provides_tools 不能绕过它）
#    config.yaml → platform_toolsets.api_server 追加 pi_workbench

# 5) Caddy（SSE 必须不缓冲）
#    hub.<你的域名> { reverse_proxy 127.0.0.1:8484 { flush_interval -1 } }
sudo systemctl reload caddy
sudo systemctl restart hermes-gateway-pi-cloud.service
```

## 验收（G0）

```bash
curl -s https://hub.<你的域名>/v1/hub/health                      # 200 + upstreamOk
curl -s -o /dev/null -w '%{http_code}\n' https://hub.<你的域名>/v1/capabilities   # 401
curl -s -H "Authorization: Bearer pi_…" https://hub.<你的域名>/v1/capabilities    # 200
curl -X POST -H "X-Pi-Admin-Key: …" https://hub.<你的域名>/v1/devices/<id>/revoke
curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer pi_…" .../v1/capabilities  # 401 device_revoked
```

管理密钥在哪、怎么拿、怎么换：见应用仓库 `docs/requirements/CLOUD_AGENT_DEVICES.md` §15.1。
一句话：`ssh … 'cat <ADMIN_KEY_FILE>'`；只有「登记新设备 / 操作别的设备」需要它，
平时对话、审批、图片、注销自己都不用。

设备登记（一次）：

```bash
curl -s -X POST https://hub.<你的域名>/v1/devices/register \
  -H "X-Pi-Admin-Key: $PI_HUB_ADMIN_KEY" -H 'Content-Type: application/json' \
  -d '{"deviceId":"<本地 device.json 的 id>","name":"<DEVICE_NAME>","scopes":["chat","dispatch"]}'
```

同一个 `deviceId` 再登记 = **换 token**（`200` + `rotated:true`，旧 token 立刻失效）——
重装、token 丢失、误注销都走这条，不会 500。

## 故障三分

| 现象 | 判断 |
| --- | --- |
| `/v1/hub/health` 连不上 | 插件没起（`journalctl -u hermes-gateway-pi-cloud`）/ Caddy vhost 错 |
| health 200 但 `upstreamOk:false` | Hermes api_server 挂了（看 `upstreamError`） |
| 401 `unauthorized` | 设备 token 错或未登记 |
| 401 `device_revoked` | 这台设备已被注销，需重新登记 |
| 403 `scope_required` | token 缺 scope |

## License

[MIT](LICENSE) © 2026 T-Chen-CN
