# DNSBox — IP 주소를 담은 호스트 이름을 위한 자체 호스팅 DNS와 HTTPS

[English](../README.md) · [Русский](README.ru.md) · [배포와 사설 네트워크](deployment.md) · [설정](configuration.md) · [업그레이드 안내](migration-v0.5.md)

DNSBox는 권한 있는 DNS 서버와 HTTPS 리버스 프록시를 결합합니다. `192-168-1-50.home.arpa` 같은 호스트 이름은 백엔드 IP 주소를 나타냅니다. DNS 응답은 **DNSBox 프록시**를 가리키며, 프록시가 TLS 연결을 종료하고 HTTP 요청을 해당 백엔드로 전달합니다. 점 또는 하이픈으로 구분한 IPv4, 하이픈으로 구분한 IPv6, WebSocket 업그레이드, 인증서 영구 저장을 지원합니다.

두 가지 TLS 모드를 제공합니다.

- **`acme`**: ACME DNS-01을 사용하여 직접 관리하는 도메인 아래의 호스트 이름에 인증서를 발급합니다. 기본 인증 기관은 Let's Encrypt입니다. 권한 있는 DNS 서버에 공용 인터넷에서 접근할 수 있어야 합니다.
- **`local`**: 공용 DNS, 인터넷 연결, 포트 포워딩 없이 사설 네트워크에서 사용하는 영구적인 로컬 인증 기관(CA)입니다. 클라이언트는 생성된 CA를 신뢰하도록 설정해야 합니다.

인증서는 DNS 호스트 이름에 적용되며, IP 주소 자체에 적용되지는 않습니다. 이 소프트웨어를 실행한다고 해서 `dnsbox.io`에 대한 관리 권한이 생기지는 않습니다. 공용 `dnsbox.io` 서비스의 가용성과 설정은 이 저장소와 별개입니다.

## 사설 네트워크에서 빠르게 시작하기

예시: DNSBox 가상 머신은 `192.168.1.2`, HTTP 애플리케이션은 `192.168.1.50:80`, 사설 DNS 영역은 `home.arpa`입니다.

환경에 맞는 [릴리스 압축 파일](https://github.com/crypto-chiefs/dnsbox/releases)을 내려받고 `checksums.txt`로 검증한 다음 실행합니다.

```bash
./dnsboxd \
  --domain=home.arpa --ip=192.168.1.2 --ns=ns1 \
  --tls-mode=local --allowed-cidrs=192.168.1.0/24 \
  --dns-listen=192.168.1.2:53 --https-listen=192.168.1.2:443 \
  --data-dir=/var/lib/dnsbox
```

프로세스에는 데이터 디렉터리에 쓸 수 있는 권한과 해당 포트를 바인딩할 수 있는 권한이 필요합니다. LAN의 DNS 리졸버가 **`home.arpa` 영역**의 질의를 `192.168.1.2`로 전달하도록 설정하세요. DNSBox는 일반적인 재귀 DNS 서비스를 제공하지 않습니다.

첫 인증서 요청 시 DNSBox는 `/var/lib/dnsbox/ca/root.crt`와 해당 개인 키를 생성합니다. **`root.crt`만** 안전하게 클라이언트로 복사하고 신뢰할 수 있는 CA 저장소에 설치하세요. 한 명령에만 신뢰할 인증서를 지정하여 테스트하려면 다음을 실행합니다.

```bash
curl --cacert root.crt \
  --resolve 192-168-1-50.home.arpa:443:192.168.1.2 \
  https://192-168-1-50.home.arpa/
```

서비스를 시작하기 전에 같은 설정에 `--issue=192-168-1-50.home.arpa`를 추가하여 CA와 서버 인증서를 미리 생성할 수도 있습니다. 로컬 모드에서는 수신 포트를 열지 않고 인증서를 저장한 뒤 종료합니다. [사설 네트워크 배포 안내](deployment.md)를 참고하세요.

## 설치

Linux와 macOS용 설치 스크립트이며, 특정 릴리스 버전으로 고정되어 있습니다.

```bash
curl --fail --location \
  https://raw.githubusercontent.com/crypto-chiefs/dnsbox/v0.5.1/scripts/install.sh \
  -o install-dnsbox.sh
# 스크립트를 검토한 다음 실행합니다.
bash install-dnsbox.sh \
  --domain=home.arpa --ip=192.168.1.2 \
  --tls-mode=local --allowed-cidrs=192.168.1.0/24 \
  --dns-listen=192.168.1.2:53 --https-listen=192.168.1.2:443
```

설치 스크립트는 압축 파일의 SHA-256 체크섬을 검증하고 `~/.dnsbox`에 설치하며, 새로 설치할 때는 영구 데이터를 `~/.dnsbox/data`에 저장합니다. systemd가 실행 중인 경우에만 systemd 서비스를 생성합니다. Calculate Linux/OpenRC를 포함해 수동으로 시작하려면 `--no-systemd`를 사용하세요.

```bash
~/.dnsbox/run-dnsbox
```

생성된 `~/.dnsbox/dnsbox.env` 파일에 설정이 저장되며 업그레이드 시에도 유지됩니다. 설치 스크립트를 다시 실행하면 실행 파일이 업그레이드됩니다. 설정을 변경하려면 기존 환경 설정 파일을 편집하세요. 설치 및 제거 스크립트는 시스템 DNS 리졸버를 변경하거나 시스템 로그를 삭제하지 않습니다. Windows에서는 압축 파일을 풀고 같은 옵션으로 `dnsboxd.exe`를 실행하세요.

## 공개적으로 신뢰되는 인증서와 NAT

ACME 모드에서는 **직접 관리하는** 도메인 또는 하위 도메인을 DNSBox 권한 DNS 서버에 위임해야 합니다. 필요한 경우 해당 네임서버의 공용 글루 레코드 또는 주소 레코드를 설정하세요. **UDP와 TCP의 53번 포트를 모두** DNSBox로 전달하고, ACME에 필요한 아웃바운드 HTTPS 연결을 허용하세요.

DNS-01에는 인바운드 80번 포트가 **필요하지 않습니다**. 443번 포트는 HTTPS 프록시를 사용하는 클라이언트에서 접근할 수 있으면 됩니다. HTTP 백엔드는 사설 네트워크에 그대로 둘 수 있습니다. `--allowed-cidrs`로 해당 네트워크를 허용하세요. 완전히 격리된 네트워크에서는 로컬 TLS 모드를 사용해야 합니다.

```bash
./dnsboxd --domain=apps.example.com --ip=203.0.113.10 --ns=ns1 \
  --acme-email=admin@example.com --data-dir=/var/lib/dnsbox
```

예시 이름과 주소를 실제 값으로 바꾸세요. `--ip`는 클라이언트가 DNSBox에 접속할 때 사용하는 주소이며 백엔드 주소가 아닙니다. IPv4 프록시는 A 레코드를, IPv6 프록시는 AAAA 레코드를 반환합니다. 백엔드가 사용하는 IP 주소 계열과는 무관합니다.

## 보안과 호환성

기본적으로 공용 IP 주소를 사용하는 백엔드만 허용됩니다. `--allowed-cidrs` 목록을 명시하면 나열된 네트워크로만 접근을 제한하여 사설 환경에서 배포할 수 있습니다. 사설 환경에서는 LAN 인터페이스에 바인딩하고 방화벽으로 보호하세요.

관리 API의 기본 주소는 `127.0.0.1:8080`입니다. 레코드를 변경하려면 bearer 토큰을 설정해야 하며, `--api-listen=`을 빈 값으로 지정하면 API가 비활성화됩니다. 기존의 인증 없는 인증서 공유 엔드포인트는 제거되었습니다. v0.5는 **영역당 하나의 DNSBox 인스턴스**를 지원하며, 여러 노드 사이의 인증서 및 챌린지 동기화는 지원하지 않습니다.

인증서와 개인 키는 데이터 디렉터리에 영구 저장됩니다. 이 디렉터리를 안전하게 백업하세요. `certs/<hostname>.crt`와 `.key` 파일은 ocserv 같은 다른 서비스에서도 사용할 수 있지만, DNSBox의 HTTP 리버스 프록시는 OpenConnect/DTLS 프록시가 아닙니다. [인증서 내보내기 안내](deployment.md#certificates-for-ocserv-or-another-service)를 참고하세요.

v0.4에서 업그레이드하기 전에 [v0.5 마이그레이션 안내](migration-v0.5.md)를 읽어보세요.

## 개발

[go.mod](../go.mod)에 명시된 Go 버전을 사용하세요.

```bash
go test -race ./...
go vet ./...
bash scripts/test-install.sh
go build ./cmd/dnsboxd
```

릴리스 CI는 위 검사를 실행한 후 Linux, macOS, Windows용 amd64 및 arm64 압축 파일을 게시합니다. [MIT 라이선스](../LICENSE)를 따릅니다.
