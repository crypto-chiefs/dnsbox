# DNSBox — HTTPS e Let's Encrypt para qualquer endereço IP

[🇬🇧 English](../README.md) | [🇷🇺 Русский](/doc/README.ru.md) | [🇪🇸 Español](/doc/README.es.md) | [🇩🇪 Deutsch](/doc/README.de.md) | [🇫🇷 Français](/doc/README.fr.md) | [🇨🇳 中文](/doc/README.zh.md) | [🇮🇳 हिंदी](/doc/README.hi.md) | [🇧🇷 Português](/doc/README.pt.md) | [🇹🇷 Türkçe](/doc/README.tr.md) | [🇮🇩 Bahasa Indonesia](/doc/README.id.md) | [🇻🇳 Tiếng Việt](/doc/README.vi.md) | [🇰🇷 한국어](/doc/README.ko.md)

[![Release](https://img.shields.io/github/v/release/crypto-chiefs/dnsbox)](https://github.com/crypto-chiefs/dnsbox/releases)
[![Go Version](https://img.shields.io/github/go-mod/go-version/crypto-chiefs/dnsbox)](../go.mod)

**DNSBox** é um servidor DNS de código aberto que permite a emissão de certificados SSL gratuitos (Let's Encrypt) para qualquer endereço IP público (IPv4 e IPv6), sem a necessidade de possuir um domínio. Acesse seu servidor, API ou dispositivo IoT via HTTPS diretamente pelo IP.

---

## 🔍 Funcionalidades

- 🔐 **Certificados SSL gratuitos** da Let's Encrypt para endereços IP
- 🌐 **Suporte para IPv4 e IPv6**
- ⚡ **Acesso HTTPS instantâneo** sem configuração de DNS
- 🔄 **Renovação automática dos certificados**
- 💡 **Funciona mesmo sem domínio** — utilize subdomínios `*.dnsbox.io`
- 🧩 **Compatível com WebSocket, API e pipelines CI/CD**
- ⚙️ **Instalação fácil** via script shell
- 📦 Dependências mínimas, binário único, inicialização sem configuração

---

## 📦 Instalação

```bash
bash <(curl -sSL https://raw.githubusercontent.com/crypto-chiefs/dnsbox/main/scripts/install.sh) --ip=167.172.5.205 --domain=dnsbox.io --ns=ns3
```

Parâmetros:
- `--ip` — seu endereço IP público (obrigatório)
- `--domain` — domínio raiz associado ao NS (ex: `dnsbox.io`)
- `--ns` — subdomínio do nameserver (ex: `ns3`)
- `--force-resolv` — desativa o systemd-resolved e define 8.8.8.8
- `--debug` — ativa modo detalhado (debug)

---

## 🌐 Como funciona

1. O DNSBox inicia um servidor de nomes que serve registros A/AAAA e TXT dinamicamente.
2. Você recebe um subdomínio como `167.172.5.205.dnsbox.io`.
3. O Let's Encrypt verifica o registro TXT `_acme-challenge` e emite o certificado.
4. O DNSBox armazena, renova e entrega automaticamente o certificado SSL.

---

## 🛠 Exemplo de uso

Após a instalação, você pode acessar seu servidor via HTTPS:

```bash
curl https://167.172.5.205.dnsbox.io
```

Ou testar o certificado SSL com OpenSSL:

```bash
openssl s_client -connect 167.172.5.205:443 -servername 167.172.5.205.dnsbox.io
```

---

## ⚙️ Detalhes técnicos

- Linguagem: Go
- Biblioteca DNS: [miekg/dns](https://github.com/miekg/dns)
- TLS: biblioteca padrão `crypto/tls`
- Cliente ACME: suporte ACME embutido (sem necessidade de certbot)
- Toda lógica é tratada em memória: requisições e desafios

---

## 🧪 Casos de uso

- 🔧 Infraestruturas DevOps sem domínio
- 📡 Dispositivos IoT com IP público
- 🧪 Ambientes de teste e homologação (staging)
- 🚀 Deploy rápido de APIs sem configurar DNS
- 🔐 Serviços de VPN ou proxy que requerem HTTPS

---

## 🔒 Segurança

Todos os desafios ACME são servidos apenas durante a validação ativa do IP. As chaves privadas TLS são armazenadas em `/var/lib/dnsbox/certs`.

---

## 🗺 Alternativa ao sslip.io e nip.io

Diferente de outras soluções:
- O DNSBox é uma **solução auto-hospedada e open-source**
- Você pode implantar sua própria estrutura `*.yourdomain.tld`
- Suporte completo a **IPv6**, ACME e certificados **sem depender de APIs de terceiros**

---

## 📜 Licença

Este projeto está licenciado sob a licença MIT. Use, modifique e compartilhe livremente.

---

## 🔗 Links úteis

- 🌍 Site do projeto: https://dnsbox.io/
- 📦 Script de instalação: [install.sh](https://github.com/crypto-chiefs/dnsbox/blob/main/scripts/install.sh)
- 📖 Documentação: em andamento

---

⭐ Se você achou este projeto útil, dê uma estrela no GitHub!
