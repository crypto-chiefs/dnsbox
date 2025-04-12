# DNSBox — HTTPS and Let's Encrypt for Any IP Address

[🇬🇧 English](../README.md) | [🇷🇺 Русский](/doc/README.ru.md) | [🇪🇸 Español](/doc/README.es.md) | [🇩🇪 Deutsch](/doc/README.de.md) | [🇫🇷 Français](/doc/README.fr.md) | [🇨🇳 中文](/doc/README.zh.md) | [🇮🇳 हिंदी](/doc/README.hi.md) | [🇧🇷 Português](/doc/README.pt.md) | [🇹🇷 Türkçe](/doc/README.tr.md) | [🇮🇩 Bahasa Indonesia](/doc/README.id.md) | [🇻🇳 Tiếng Việt](/doc/README.vi.md) | [🇰🇷 한국어](/doc/README.ko.md)

[![Release](https://img.shields.io/github/v/release/crypto-chiefs/dnsbox)](https://github.com/crypto-chiefs/dnsbox/releases)
[![Go Version](https://img.shields.io/github/go-mod/go-version/crypto-chiefs/dnsbox)](../go.mod)

**DNSBox** — это open-source DNS-сервер, позволяющий выпускать бесплатные SSL-сертификаты (Let's Encrypt) для любых публичных IP-адресов (IPv4 и IPv6) без владения доменом. Получите HTTPS-доступ к серверу, API или IoT-устройству напрямую по IP.

---

## 🔍 Возможности

- 🔐 **Бесплатные SSL-сертификаты** от Let's Encrypt для IP-адресов
- 🌐 **Поддержка IPv4 и IPv6**
- ⚡ **Мгновенное получение HTTPS-доступа** без DNS-конфигурации
- 🔄 **Автоматическое продление сертификатов**
- 💡 **Работает даже без домена** — используйте поддомены `*.dnsbox.io`
- 🧩 **Совместим с WebSocket, API и CI/CD-сценариями**
- ⚙️ **Легкий установщик** через shell-скрипт
- 📦 Минимальные зависимости, одна бинарь, zero-config запуск

---

## 📦 Установка

```bash
bash <(curl -sSL https://raw.githubusercontent.com/crypto-chiefs/dnsbox/main/scripts/install.sh) --ip=167.172.5.205 --domain=dnsbox.io --ns=ns3
```

Параметры:
- `--ip` — ваш публичный IP-адрес (обязательно)
- `--domain` — корневой домен, к которому привязан NS (например, `dnsbox.io`)
- `--ns` — поддомен nameserver'а (например, `ns3`)
- `--force-resolv` — отключить systemd-resolved и выставить 8.8.8.8
- `--debug` — verbose режим

---

## 🌐 Как это работает

1. DNSBox поднимает nameserver, отдающий A/AAAA и TXT-записи на лету.
2. Вы получаете поддомен `167.172.5.205.dnsbox.io`.
3. Let's Encrypt проверяет наличие `_acme-challenge` TXT-записи и выдает сертификат.
4. DNSBox автоматически сохраняет, обновляет и отдает SSL-сертификат.

---

## 🛠 Пример использования

После установки, вы можете подключаться к своему серверу по HTTPS:

```bash
curl https://167.172.5.205.dnsbox.io
```

Или протестировать SSL через OpenSSL:

```bash
openssl s_client -connect 167.172.5.205:443 -servername 167.172.5.205.dnsbox.io
```

---

## ⚙️ Под капотом

- Язык: Go
- DNS-библиотека: [miekg/dns](https://github.com/miekg/dns)
- TLS: стандартный `crypto/tls`
- ACME client: встроенная поддержка ACME (без certbot)
- Логика на лету: все DNS-запросы и challenge’ы — в памяти

---

## 🧪 Применение

- 🔧 DevOps-инфраструктура без доменов
- 📡 IoT-устройства с публичным IP
- 🧪 Лабораторные среды, staging-серверы
- 🚀 Быстрый деплой API без настройки DNS
- 🔐 VPN/Proxy-сервисы, требующие HTTPS

---

## 🔒 Безопасность

Все challenge-запросы Let's Encrypt обслуживаются только при валидации текущих IP. Секретные ключи TLS сохраняются в `/var/lib/dnsbox/certs`.

---

## 🗺 Альтернатива sslip.io и nip.io

В отличие от существующих сервисов:
- DNSBox — **самостоятельное open-source решение**
- Вы можете развернуть свой собственный `*.yourdomain.tld`
- Поддерживает **IPv6**, ACME и сертификаты **без стороннего API**

---

## 📜 Лицензия

Проект распространяется под лицензией MIT. Используйте свободно, форкайте, расширяйте.

---

## 🔗 Полезные ссылки

- 🌍 Сайт проекта: https://dnsbox.io/
- 📦 Установка: [install.sh](https://github.com/crypto-chiefs/dnsbox/blob/main/scripts/install.sh)
- 📖 Документация: в процессе

---

⭐ Если проект оказался полезен, не забудьте поставить ⭐ в GitHub!
