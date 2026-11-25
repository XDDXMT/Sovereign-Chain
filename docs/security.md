# 信任、撤权与发布

SC-EE-3 在隧道的两个端点之间认证身份和数据。运行代理或应用的主机能接触该端明文。项目自带的测试覆盖具体实现行为，独立的密码协议审计仍待完成。

## 私钥与角色

`init-pki` 在新的目标目录内生成根 CA、中级 CA 和具名端点。终端直接信任配置的中级 CA 公共证书。根 CA、中级 CA 的私钥用签发口令加密并留在签发方。

| 目录 | 可接收该目录的角色 |
| --- | --- |
| `authority/` | 签发管理员 |
| `server/` | 对应服务端，仅含该端私钥、证书和信任锚 |
| `client/` | 对应客户端，仅含该端私钥、证书和信任锚 |

默认凭据位于用户主目录 `.sovereign-chain/pki`。使用 `SC_PKI_DIR` 切换父目录，或设置 `SC_CA_CERT_FILE`、`SC_CLIENT_CERT_FILE`、`SC_CLIENT_KEY_FILE`、`SC_SERVER_CERT_FILE`、`SC_SERVER_KEY_FILE`。Windows 上应核实实际目录与文件 ACL，尤其是跨机器复制之后。

初次签发需要交互口令或 `SC_CA_KEY_PASSWORD`。端点私钥在签发时设置相应的 `SC_CLIENT_KEY_PASSWORD`、`SC_SERVER_KEY_PASSWORD` 可获得口令保护。使用加密端点密钥时，相应服务必须能读取口令。省略端点口令时，私钥依赖账户和文件权限保护。

## 历史密钥与轮换

新版按 DER 编码 SubjectPublicKeyInfo 的 SHA-256 识别已知历史分发凭据。五份已审旧归档对应的 15 个不同公钥已列入拒绝清单，包括签发者与端点。重新用同一把旧密钥签发证书也会被拒绝。这份清单只覆盖已识别的材料。

1. 在每个部署端运行 `sovereign-chain trust-info --role server` 或 `--role client`，登记实际信任锚的公钥指纹、到期时间和原生加密库。此命令只读取公共证书，可在换证前识别已退役的信任锚。
2. 如果旧包离开了签发方控制，生成独立的新签发体系，给每个部署单独签发证书。在受控通道核验新 CA 的指纹，然后分发对应角色的文件。
3. 对正在运行的监听器，在**原配置路径**用完整临时文件逐个原子替换，或切换指向完整版本目录的受控目录引用。监听器约每秒核验文件元数据，变更时重读并校验配对、信任、有效期和 CRL，再发布完整快照。有效替换、中途缺失、证书或 CRL 到期均会终止使用旧快照的连接。无效期间拒绝新连接，完整材料恢复后自动接入。
4. 更改路径、进程环境或密钥口令时，需要重启服务以载入新配置。对仍运行旧版本的进程也应主动停止旧会话并重启。逐个验证新身份可用、旧身份拒绝，并撤回旧分发包。真实接收方、存量旧客户端和现网指纹需由部署方盘点。

单次直连客户端会在建立连接时读取凭据。旧程序的信任缓存与已发出的文件需要在实际部署中处置。

## 身份与吊销策略

端点必须使用 Ed25519 身份密钥，具备相应角色 EKU 和签名用途。DNS SAN 与 IP SAN 分型匹配。两端拒绝无法处理的关键扩展，受额外约束且当前实现不能完整解释的 CA 也会被拒绝。证书签名验证支持 Ed25519，以及本项目验证配置中允许的 RSA、ECDSA 和 SHA-2 组合。服务端接受的客户端身份由 `SC_ALLOWED_CLIENT_NAMES` 配置。

`SC_CRL_FILE` 接受 PEM 或 DER 编码的**完整、直接、全范围** CRL。要求签发者可签 CRL，校验签名、签发者、有效期、已提供的签发者标识以及条目范围。增量、分区、间接列表和未支持的扩展被拒绝。监听进程在同一 CA 下拒绝倒退的 CRL 序号或签发时间。跨进程重启的版本管理由部署系统承担。

`SC_REQUIRE_CRL=1` 时缺少 CRL 会拒绝认证。显式布尔值支持 `0/1`、`false/true`，无效值会报错。设置了路径的 CRL 即使在可选模式下也必须有效。CRL 或凭据文件变更会废止现有代理会话；单个会话还受对端证书有效期和最长会话期限约束。

## 代理接入与异常结束

`client-proxy` 要求显式选择接入方式。共享主机和网络入口应提供 `--ingress-pki-dir` 与单个 `--ingress-client-name`。入站凭据使用独立目录中的 `server/`，进程同时需要自己的上游 `client/`。入站覆盖项使用 `SC_INGRESS_SERVER_NAME`、`SC_INGRESS_CA_CERT_FILE`、`SC_INGRESS_SERVER_CERT_FILE`、`SC_INGRESS_SERVER_KEY_FILE`、`SC_INGRESS_SERVER_KEY_PASSWORD`、`SC_INGRESS_CRL_FILE`、`SC_INGRESS_REQUIRE_CRL`。用不同的监听实例与上游身份表达不同权限。

`--trusted-loopback` 允许普通 TCP 应用在专用单用户主机上使用代理身份。绑定地址必须是回环 IP 字面量，连接处理还会检查实际本地和对端地址。回环端口不能隔离同机用户。远端目标始终由服务端代理配置。

单连接两个方向共用一个工作线程，在对端可写时才继续转发。空闲与不完整入站记录默认限时 300 秒，每个待写批次 30 秒，首个半关闭至结束 60 秒，总寿命 8 小时。长文件传输或长时静默业务可通过 README 中的参数调整为有限正数。

收到通过认证的 FIN，代理只关闭对应方向。隧道截断、完整性失败或转发超时，代理会请求 TCP 中止并记录原因。操作系统对终端可见的错误因平台和套接字状态而异。已交付的应用数据不能撤回；涉及提交、文件写入或支付的应用应验证自身最终确认或预期长度和摘要。

## 依赖与交付

最低 Python 为 3.11。运行库 `cryptography` 从 50.0.2 起，构建后端 `setuptools` 从 84.2.1 起。CI 使用 `requirements/` 中按版本与哈希锁定的发行文件，在隔离的审计作业中以 pip-audit 核验运行和构建依赖。更新约束时须重新编译锁、审查变更并执行全套 CI。

`trust-info` 会打印 `cryptography` 实际使用的 OpenSSL。2026-11-25 的 Windows 验收轮子加载 OpenSSL 4.0.3。SC 握手和会话固定使用 12 字节 nonce、单段非空 AAD。部署方仍应跟踪供应商原生补丁，升级获支持的轮子或使用经回归的已修补后端；Python 包公告的零命中不代表原生后端已打全补丁。[OpenSSL 公告](https://openssl-library.org/news/vulnerabilities-4.0/)

发布检查会比较制品与受信源码树、核对包成员全集、入口和版本，重算 wheel RECORD 并输出整包摘要。完整性校验依赖可信的构建源码；合并至 master 后，四组测试与依赖审计通过的工作流会保存 verified-distributions 制品、SHA256SUMS 和 GitHub 构建来源证明。可用 gh attestation verify 加文件名和 --repo XDDXMT/Sovereign-Chain 核验该次 CI 生成的发行文件，并核对来源分支与工作流。对 PR 和本机构建不签发主分支证明。仓库要求通过 PR 和受保护的 CI 检查，外部 Actions 固定到完整提交 SHA。

上一开发版本的验收保存在 [2.1.0.dev0 的记录](https://github.com/XDDXMT/Sovereign-Chain/blob/470a0e47fc4d12e5e4f54c2d0d81be6ab90e3856/docs/security.md)。
