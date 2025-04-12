# DNSBox — 모든 IP 주소를 위한 HTTPS 및 Let's Encrypt

[🇬🇧 English](../README.md) | [🇷🇺 Русский](/doc/README.ru.md) | [🇪🇸 Español](/doc/README.es.md) | [🇩🇪 Deutsch](/doc/README.de.md) | [🇫🇷 Français](/doc/README.fr.md) | [🇨🇳 中文](/doc/README.zh.md) | [🇮🇳 हिंदी](/doc/README.hi.md) | [🇧🇷 Português](/doc/README.pt.md) | [🇹🇷 Türkçe](/doc/README.tr.md) | [🇮🇩 Bahasa Indonesia](/doc/README.id.md) | [🇻🇳 Tiếng Việt](/doc/README.vi.md) | [🇰🇷 한국어](/doc/README.ko.md)

[![Release](https://img.shields.io/github/v/release/crypto-chiefs/dnsbox)](https://github.com/crypto-chiefs/dnsbox/releases)
[![Go Version](https://img.shields.io/github/go-mod/go-version/crypto-chiefs/dnsbox)](../go.mod)

**DNSBox**는 오픈 소스 DNS 서버로, 도메인 없이도 모든 공개 IP 주소(IPv4 및 IPv6)에 대해 무료 SSL 인증서(Let's Encrypt)를 발급할 수 있습니다. HTTPS를 통해 IP 기반으로 서버, API 또는 IoT 장치에 직접 액세스할 수 있습니다.

---

## 🔍 주요 기능

- 🔐 **Let's Encrypt로부터 무료 SSL 인증서 발급**
- 🌐 **IPv4 및 IPv6 지원**
- ⚡ **DNS 설정 없이 즉시 HTTPS 액세스**
- 🔄 **인증서 자동 갱신**
- 💡 **도메인 없이 작동** — `*.dnsbox.io` 서브도메인 사용
- 🧩 **WebSocket, API, CI/CD 환경과 호환**
- ⚙️ **간단한 설치** — 셸 스크립트 기반
- 📦 최소 의존성, 단일 바이너리, 무설정 실행

---

## 📦 설치 방법

```bash
bash <(curl -sSL https://raw.githubusercontent.com/crypto-chiefs/dnsbox/main/scripts/install.sh) --ip=167.172.5.205 --domain=dnsbox.io --ns=ns3
```

인자 설명:
- `--ip` — 사용자의 공개 IP 주소 (필수)
- `--domain` — NS에 연결된 루트 도메인 (예: `dnsbox.io`)
- `--ns` — 네임서버용 서브도메인 (예: `ns3`)
- `--force-resolv` — systemd-resolved 비활성화 및 8.8.8.8 설정
- `--debug` — 디버그 모드 활성화

---

## 🌐 작동 방식

1. DNSBox는 A/AAAA 및 TXT 레코드를 실시간으로 제공하는 네임서버를 실행합니다.
2. 예: `167.172.5.205.dnsbox.io` 와 같은 서브도메인을 부여받습니다.
3. Let's Encrypt가 `_acme-challenge` TXT 레코드를 확인하고 인증서를 발급합니다.
4. DNSBox는 인증서를 자동 저장, 갱신 및 제공합니다.

---

## 🛠 사용 예시

설치 후 HTTPS로 서버에 연결할 수 있습니다:

```bash
curl https://167.172.5.205.dnsbox.io
```

OpenSSL로 SSL 테스트:

```bash
openssl s_client -connect 167.172.5.205:443 -servername 167.172.5.205.dnsbox.io
```

---

## ⚙️ 기술 세부사항

- 언어: Go
- DNS 라이브러리: [miekg/dns](https://github.com/miekg/dns)
- TLS: 기본 `crypto/tls`
- ACME 클라이언트: 내장 ACME 지원 (certbot 불필요)
- 모든 로직은 메모리 내에서 처리됨

---

## 🧪 사용 사례

- 🔧 도메인 없는 DevOps 인프라
- 📡 공개 IP를 가진 IoT 장치
- 🧪 테스트 및 스테이징 환경
- 🚀 DNS 설정 없이 빠른 API 배포
- 🔐 HTTPS가 필요한 VPN/프록시 서비스

---

## 🔒 보안

Let's Encrypt 챌린지는 유효한 IP 검증 동안에만 처리됩니다. TLS 개인 키는 `/var/lib/dnsbox/certs`에 저장됩니다.

---

## 🗺 sslip.io 및 nip.io의 대안

다른 서비스와는 달리:
- DNSBox는 **셀프호스팅 가능한 오픈 소스 솔루션**
- 자신의 `*.yourdomain.tld` 인프라 배포 가능
- **IPv6**, ACME 및 **타사 API 없이** 인증서 지원

---

## 📜 라이선스

본 프로젝트는 MIT 라이선스로 제공됩니다. 자유롭게 사용, 포크, 수정 가능합니다.

---

## 🔗 유용한 링크

- 🌍 공식 웹사이트: https://dnsbox.io/
- 📦 설치 스크립트: [install.sh](https://github.com/crypto-chiefs/dnsbox/blob/main/scripts/install.sh)
- 📖 문서화: 진행 중

---

⭐ 유용하게 느끼셨다면 GitHub에서 ⭐ 을 눌러주세요!
