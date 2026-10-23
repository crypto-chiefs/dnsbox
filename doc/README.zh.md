# DNSBox

DNSBox 将权威 DNS 服务器与 HTTPS 反向代理结合。像 `192-168-1-50.home.arpa` 这样的主机名编码后端 IP；DNS 响应指向 DNSBox 代理地址。

- `--tls-mode=local`：用于私有网络，无需互联网或端口转发。客户端必须信任本地 CA。
- `--tls-mode=acme`：为您控制的 DNS 区域中的主机名签发证书。需要通过 UDP 和 TCP 53 提供公共 DNS；DNS-01 不需要开放入站 80 端口。
- 私有后端需要显式配置 `--allowed-cidrs`。
- 证书针对 DNS 主机名，而非裸 IP 地址。安装 DNSBox 不会获得对 `dnsbox.io` 的控制权。

旧版安装说明已为 v0.5 更新替换。完整的最新文档目前提供英文版本：

[使用指南](../README.md) · [私有网络与 NAT](deployment.md) · [配置](configuration.md) · [迁移](migration-v0.5.md)