# 天启御链 · Sovereign-Chain

Sovereign-Chain 用证书验证 TCP 连接两端的身份，再用 SC-EE-3 加密传输数据。可以直接运行加密回显示例，也可以给已有 TCP 服务接上一对代理。本整理版的软件包版本为 `2.1.0.dev0`。

## 三步跑通加密回显

以下命令在 Windows PowerShell 中执行，需要 Python 3.10 或更高版本。示例使用 3.13。

**1. 在项目根目录安装。**

```powershell
Set-Location G:\Sovereign-Chain
py -3.13 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
```

**2. 生成一套新证书并启动服务端。**

```powershell
.\.venv\Scripts\python.exe -m sovereign_chain init-pki
.\.venv\Scripts\python.exe -m sovereign_chain server
```

首次初始化会提示设置 CA 私钥口令，默认输出在用户主目录的 `.sovereign-chain/pki`。已有目录会受到覆盖保护。同一套凭据只需初始化一次。服务端默认在 `127.0.0.1:5555` 等待。

**3. 打开第二个 PowerShell，发送一条消息。**

```powershell
Set-Location G:\Sovereign-Chain
.\.venv\Scripts\python.exe -m sovereign_chain client --message "hello"
```

成功时会收到 `echo: hello`。省略 `--message` 可进入交互模式。服务端可用 Ctrl+C 停止。

## 接入已有 TCP 服务

以本机已有的 HTTP 服务 `127.0.0.1:8000` 为例。在两个终端分别从项目根目录运行下面的命令，保持两个代理运行。

```powershell
.\.venv\Scripts\python.exe -m sovereign_chain server-proxy --target-port 8000
```

```powershell
.\.venv\Scripts\python.exe -m sovereign_chain client-proxy
```

现在访问 `http://127.0.0.1:3398/` 就会经过隧道抵达该 HTTP 服务。默认拓扑如下。

```text
应用 → 本地代理 :3398  ═══ SC-EE-3 加密 TCP ═══  远端代理 :25558 → 目标服务 :8000
```

两个代理都能看到交付给应用的字节。代理与应用之间的链路由应用协议自行保护。跨机器时，服务端代理用 `--listen-host` 绑定目标网卡，客户端代理用 `--remote-host` 指向它。每个命令的 `--help` 可查看参数。

## 配置

地址参数优先于环境变量。默认监听 IPv4 回环地址。证书路径和套件在启动相应进程前设置。

| 用途 | 配置与默认值 |
| --- | --- |
| 直连服务端监听 | `SC_LISTEN_HOST`、`SC_LISTEN_PORT`，默认 `127.0.0.1:5555` |
| 客户端连接对端 | `SC_SERVER_HOST`、`SC_SERVER_PORT`，直连默认端口 5555，客户端代理默认 25558 |
| 客户端代理入口 | `SC_CLIENT_PROXY_LISTEN_HOST`、`SC_CLIENT_PROXY_LISTEN_PORT`，默认 `127.0.0.1:3398` |
| 服务端代理入口与目标 | `SC_PROXY_LISTEN_HOST`、`SC_PROXY_LISTEN_PORT` 默认 `127.0.0.1:25558`，`SC_PROXY_TARGET_HOST`、`SC_PROXY_TARGET_PORT` 默认 `127.0.0.1:8000` |
| 并发连接 | `--max-connections` 或 `SC_MAX_CONNECTIONS`，每个监听进程默认 64 |
| 凭据与身份 | `SC_PKI_DIR` 为包含角色子目录的目录。`SC_SERVER_NAME` 默认 `Sovereign-Chain-Server`，`SC_ALLOWED_CLIENT_NAMES` 默认 `Sovereign-Chain-Client`，多个客户端名称用逗号分隔 |
| 密码套件 | `SC_CIPHER_SUITE` 默认 `CHACHA20-POLY1305`，也可选 `AES-256-GCM-SIV`，两端须一致 |
| 消息填充 | `SC_MIN_PADDING_BYTES`、`SC_MAX_PADDING_BYTES` 默认 0 和 32，协议允许的最大值为 256 |

`init-pki --out` 仅选择生成位置。自定义位置后，各终端通过 `SC_PKI_DIR` 指向相应目录。分机部署、私钥口令、吊销配置及旧凭据处置见 [安全说明](docs/security.md)。

## 目录

```text
src/sovereign_chain/
  __main__.py                五个命令及加密回显示例
  client.py、server.py       两端握手
  handshake.py、wire.py      共享密钥派生、握手记录和 TCP 帧
  security.py                证书验证、双向会话、认证加密和填充
  credentials.py、pki.py     角色凭据加载和首次签发
  service.py、proxy.py       有界监听、停止和双向转发
tests/                       协议、安全、代理生命周期及打包策略测试
docs/                        协议流程和安全边界
tools/verify_dist.py         检查 wheel 和源码包内容
.github/workflows/ci.yml     Windows / Linux 自动测试及构建
pyproject.toml、MANIFEST.in   依赖、入口及包内容规则
dist/                        本次构建的 wheel 和源码包
```

## 测试与打包

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
.\.venv\Scripts\python.exe -m pip install build
.\.venv\Scripts\python.exe -m build
.\.venv\Scripts\python.exe tools\verify_dist.py dist
```

检查器会打开生成的两个包，验证成员白名单并检查私钥 PEM 标记。安装已构建的 wheel 也可以直接使用 `sovereign-chain` 命令。握手顺序、密钥演进、代理关闭语义见 [协议说明](docs/protocol.md)。项目保留原始 [许可证](LICENSE)。
