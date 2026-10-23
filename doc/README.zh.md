# DNSBox — 面向 IP 编码主机名的自托管 DNS 与 HTTPS

[English](../README.md) · [Русский](README.ru.md) · [部署与私有网络](deployment.md) · [配置](configuration.md) · [升级说明](migration-v0.5.md)

DNSBox 将权威 DNS 服务器与 HTTPS 反向代理结合起来。`192-168-1-50.home.arpa` 这样的主机名表示一个后端 IP 地址。DNS 响应指向 **DNSBox 代理**，由代理终止 TLS 连接，并通过 HTTP 将请求转发到后端。它支持点分或连字符分隔的 IPv4、连字符分隔的 IPv6、WebSocket 协议升级，以及证书持久化存储。

提供两种 TLS 模式：

- **`acme`**：通过 ACME DNS-01 为您控制的域名下的主机名签发证书，默认使用 Let's Encrypt。您的权威 DNS 必须能够从公网访问。
- **`local`**：为私有网络提供持久化的本地证书颁发机构（CA），无需公共 DNS、互联网连接或端口转发。客户端必须信任生成的 CA。

证书适用于 DNS 主机名，而非裸 IP 地址。运行此软件并不会获得对 `dnsbox.io` 的控制权。公共 `dnsbox.io` 服务的可用性和配置与本仓库相互独立。

## 私有网络快速入门

示例：DNSBox 虚拟机的地址为 `192.168.1.2`，HTTP 应用位于 `192.168.1.50:80`，私有 DNS 区域为 `home.arpa`。

下载适合您平台的[发行版压缩包](https://github.com/crypto-chiefs/dnsbox/releases)，使用 `checksums.txt` 校验文件，然后运行：

```bash
./dnsboxd \
  --domain=home.arpa --ip=192.168.1.2 --ns=ns1 \
  --tls-mode=local --allowed-cidrs=192.168.1.0/24 \
  --dns-listen=192.168.1.2:53 --https-listen=192.168.1.2:443 \
  --data-dir=/var/lib/dnsbox
```

进程需要具备数据目录的写入权限，以及绑定这些端口的权限。请配置局域网 DNS 解析器，将 **`home.arpa` 区域**的查询转发到 `192.168.1.2`；DNSBox 不提供通用的递归 DNS 解析服务。

首次请求证书时，DNSBox 会创建 `/var/lib/dnsbox/ca/root.crt` 及其私钥。请通过安全方式将 **`root.crt` 这一个文件**复制到客户端，并将其安装到受信任的 CA 存储中。若只想为单条命令指定信任证书，可使用以下命令测试：

```bash
curl --cacert root.crt \
  --resolve 192-168-1-50.home.arpa:443:192.168.1.2 \
  https://192-168-1-50.home.arpa/
```

您也可以在启动服务前，使用相同配置并添加 `--issue=192-168-1-50.home.arpa`，预先创建 CA 和服务器证书。在本地模式下，该操作会写入证书后退出，不会开启监听端口。请参阅[私有网络部署指南](deployment.md)。

## 安装

Linux 和 macOS 安装脚本（固定到对应发行版）：

```bash
curl --fail --location \
  https://raw.githubusercontent.com/crypto-chiefs/dnsbox/v0.5.2/scripts/install.sh \
  -o install-dnsbox.sh
# 检查脚本内容后运行：
bash install-dnsbox.sh \
  --domain=home.arpa --ip=192.168.1.2 \
  --tls-mode=local --allowed-cidrs=192.168.1.0/24 \
  --dns-listen=192.168.1.2:53 --https-listen=192.168.1.2:443
```

安装脚本会验证压缩包的 SHA-256 校验和，将程序安装到 `~/.dnsbox`，并在全新安装时使用 `~/.dnsbox/data` 保存持久化数据。仅在 systemd 正在运行时才会创建 systemd 服务。如需手动启动，包括在 Calculate Linux/OpenRC 上使用，请添加 `--no-systemd`：

```bash
~/.dnsbox/run-dnsbox
```

生成的 `~/.dnsbox/dnsbox.env` 文件保存配置，并在升级时保留。重新运行安装脚本会升级二进制文件；如需修改设置，请编辑已有的环境配置文件。安装和卸载脚本都不会更改系统 DNS 解析器，也不会删除系统日志。在 Windows 上，解压发行版压缩包后，使用相同参数运行 `dnsboxd.exe`。

## 公共证书与 NAT

在 ACME 模式下，需要将**您控制的**域名或子域名委派给 DNSBox 权威服务器，并按需为其名称服务器配置公共 glue 记录或地址记录。请将 **UDP 和 TCP 的 53 端口都转发**到 DNSBox，并允许用于 ACME 的出站 HTTPS 连接。

DNS-01 **不需要**开放入站 80 端口。443 端口只需能被使用 HTTPS 代理的客户端访问。HTTP 后端可以继续位于私有网络中：使用 `--allowed-cidrs` 允许访问其所在网段。完全隔离的网络则必须使用本地 TLS 模式。

```bash
./dnsboxd --domain=apps.example.com --ip=203.0.113.10 --ns=ns1 \
  --acme-email=admin@example.com --data-dir=/var/lib/dnsbox
```

请将示例中的名称和地址替换为您自己的值。`--ip` 是客户端用于访问 DNSBox 的地址，而不是后端地址。IPv4 代理返回 A 记录，IPv6 代理返回 AAAA 记录，与后端使用的 IP 地址族无关。

## 多个 DNS 节点与 ACME

在每个节点上配置相同的静态 `--nameservers` 列表。标签必须唯一，地址必须是单播 IP 字面量；本机的 `--ns` 和 `--ip` 必须与其中一项一致。所有节点发布相同的 NS 集合、其他节点的地址和 SOA 主服务器。不配置此选项时，DNSBox 只发布自己的名称服务器。父区域的委派、glue 记录以及自定义 NS 地址覆盖必须保持一致。

在多个权威节点上使用 ACME 时，请为每个节点配置 `--cluster-file`，以复制临时 DNS-01 TXT 值。所有节点应使用相同的区域、后端访问策略和自定义记录。第一个节点的示例：

```bash
./dnsboxd --domain=apps.example.com --ip=203.0.113.10 --ns=ns1 \
  --nameservers=ns1=203.0.113.10,ns2=203.0.113.11,ns3=203.0.113.12 \
  --cluster-file=/etc/dnsbox/cluster.json --data-dir=/var/lib/dnsbox
```

该节点的 `cluster.json`：

```json
{
  "listen": "0.0.0.0:8443",
  "certificate": "cluster-node.crt",
  "private_key": "cluster-node.key",
  "ca_certificate": "cluster-ca.crt",
  "peers": ["https://203.0.113.11:8443", "https://203.0.113.12:8443"]
}
```

每个节点都必须通过包含 IP 和端口的 HTTPS URL 显式列出所有其他节点。仅允许这些节点访问集群端口。使用专用的集群 CA，并为每个节点配置独立的证书和私钥；证书的 SAN 必须包含该节点的 IP，并同时允许服务器和客户端身份验证。相对路径以 JSON 文件所在目录为基准。保护 CA 和 TLS 文件，将 CA 私钥离线保存。节点通过双向 TLS 相互认证；集群仅复制临时 TXT 值，不传输 HTTPS 证书、私钥或本地模式的 CA。对应的环境变量为 `DNSBOX_NAMESERVERS` 和 `DNSBOX_CLUSTER_FILE`。

## 区域根名称的 ALIAS 记录

要将区域根名称指向外部托管服务的主机名，请在 `--records-file` 指定的文件中加入：

```text
apps.example.com ALIAS landing.example.net.
```

请在托管服务上配置您的根域名和 HTTPS。DNSBox 在 DNS 服务就绪前解析目标，在后台刷新地址，并使用缓存的 A/AAAA 记录响应查询，不在查询处理过程中进行网络解析。首次解析失败会阻止启动；缓存超过一小时未成功更新时，A/AAAA 查询返回 SERVFAIL。ALIAS 仅允许用于区域根名称，目标必须位于本区域之外，且不能与同名 A、AAAA 或 CNAME 共存。NS、SOA、TXT、MX 和基于 IP 的代理主机名仍可使用。静态名称服务器列表、集群 TXT 复制和 ALIAS 需要 v0.5.2 或更新版本。

## 安全性与兼容性

默认情况下，只允许访问使用公共 IP 地址的后端。显式设置 `--allowed-cidrs` 列表后，访问范围会被限制在所列网段内，从而支持私有网络部署。私有部署应绑定到局域网接口，并置于防火墙保护之下。

管理 API 默认监听 `127.0.0.1:8080`。修改记录需要配置 bearer 令牌；将 `--api-listen=` 设为空值可禁用该 API。旧版无需身份验证的证书共享接口已移除。每个节点保留独立的证书存储。

证书和私钥会持久化保存在数据目录中。请安全地备份该目录。`certs/<hostname>.crt` 和 `.key` 文件可供 ocserv 等其他服务使用，但 DNSBox 的 HTTP 反向代理不是 OpenConnect/DTLS 代理。请参阅[证书导出说明](deployment.md#certificates-for-ocserv-or-another-service)。

从 v0.4 升级前，请阅读 [v0.5 迁移说明](migration-v0.5.md)。

## 开发

请使用 [go.mod](../go.mod) 中声明的 Go 版本。

```bash
go test -race ./...
go vet ./...
bash scripts/test-install.sh
go build ./cmd/dnsboxd
```

发行流程的 CI 会先运行这些检查，再发布面向 Linux、macOS 和 Windows 的 amd64 与 arm64 压缩包。采用 [MIT 许可证](../LICENSE)。
