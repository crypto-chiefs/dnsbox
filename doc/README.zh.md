# DNSBox — 为任意 IP 地址启用 HTTPS 和 Let's Encrypt

[🇬🇧 English](../README.md) | [🇷🇺 Русский](/doc/README.ru.md) | [🇪🇸 Español](/doc/README.es.md) | [🇩🇪 Deutsch](/doc/README.de.md) | [🇫🇷 Français](/doc/README.fr.md) | [🇨🇳 中文](/doc/README.zh.md) | [🇮🇳 हिंदी](/doc/README.hi.md) | [🇧🇷 Português](/doc/README.pt.md) | [🇹🇷 Türkçe](/doc/README.tr.md) | [🇮🇩 Bahasa Indonesia](/doc/README.id.md) | [🇻🇳 Tiếng Việt](/doc/README.vi.md) | [🇰🇷 한국어](/doc/README.ko.md)

[![Release](https://img.shields.io/github/v/release/crypto-chiefs/dnsbox)](https://github.com/crypto-chiefs/dnsbox/releases)
[![Go Version](https://img.shields.io/github/go-mod/go-version/crypto-chiefs/dnsbox)](../go.mod)

**DNSBox** 是一个开源 DNS 服务器，可为任意公共 IP 地址（IPv4 和 IPv6）签发免费的 SSL 证书（Let's Encrypt），无需拥有域名。您可以通过 IP 直接以 HTTPS 访问服务器、API 或 IoT 设备。

---

## 🔍 功能特点

- 🔐 来自 Let's Encrypt 的 **免费 SSL 证书**
- 🌐 **支持 IPv4 和 IPv6**
- ⚡ **无需 DNS 配置即可获得 HTTPS 访问**
- 🔄 **自动续期 SSL 证书**
- 💡 **无需拥有域名**，可使用 `*.dnsbox.io` 子域名
- 🧩 **兼容 WebSocket、API 与 CI/CD 场景**
- ⚙️ **通过 shell 脚本安装，快速上手**
- 📦 依赖极少，单一可执行文件，零配置启动

---

## 📦 安装方式

```bash
bash <(curl -sSL https://raw.githubusercontent.com/crypto-chiefs/dnsbox/main/scripts/install.sh) --ip=167.172.5.205 --domain=dnsbox.io --ns=ns3
```

参数说明：
- `--ip`：您的公共 IP 地址（必填）
- `--domain`：绑定到 NS 的根域名（例如 `dnsbox.io`）
- `--ns`：nameserver 的子域（如 `ns3`）
- `--force-resolv`：禁用 systemd-resolved 并设定为 8.8.8.8
- `--debug`：开启调试模式，输出详细日志

---

## 🌐 工作原理

1. DNSBox 启动一个 nameserver，动态响应 A/AAAA 和 TXT 记录。
2. 您获得一个子域名，例如 `167.172.5.205.dnsbox.io`。
3. Let's Encrypt 验证 `_acme-challenge` TXT 记录并签发证书。
4. DNSBox 自动保存、续期并分发 SSL 证书。

---

## 🛠 使用示例

安装完成后，您可以通过 HTTPS 访问服务器：

```bash
curl https://167.172.5.205.dnsbox.io
```

或使用 OpenSSL 验证证书：

```bash
openssl s_client -connect 167.172.5.205:443 -servername 167.172.5.205.dnsbox.io
```

---

## ⚙️ 技术细节

- 编程语言：Go
- DNS 库：[miekg/dns](https://github.com/miekg/dns)
- TLS 实现：Go 标准库 `crypto/tls`
- ACME 客户端：内置实现，无需 certbot
- 内存中处理所有 DNS 请求与验证挑战

---

## 🧪 使用场景

- 🔧 无域名的 DevOps 基础设施
- 📡 公网 IP 的 IoT 设备
- 🧪 测试环境、预发布环境
- 🚀 快速部署 API，无需设置 DNS
- 🔐 需要 HTTPS 的 VPN 或代理服务

---

## 🔒 安全说明

所有 Let's Encrypt 验证请求仅在有效验证时响应。TLS 私钥保存在 `/var/lib/dnsbox/certs`。

---

## 🗺 替代方案：sslip.io 与 nip.io

与这些服务不同：
- DNSBox 是一个 **完全自托管的开源解决方案**
- 您可以部署自己的 `*.yourdomain.tld`
- 支持 **IPv6**、ACME 与 **无需第三方 API 的证书签发**

---

## 📜 许可证

本项目使用 MIT 许可证，免费使用、修改与再发布。

---

## 🔗 相关链接

- 🌍 项目网站：https://dnsbox.io/
- 📦 安装脚本：[install.sh](https://github.com/crypto-chiefs/dnsbox/blob/main/scripts/install.sh)
- 📖 文档：撰写中...

---

⭐ 如果您觉得这个项目有帮助，请在 GitHub 上点个 ⭐ 吧！
