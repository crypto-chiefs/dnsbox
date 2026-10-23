# DNSBox

DNSBox는 권한 있는 DNS 서버와 HTTPS 리버스 프록시를 결합합니다. `192-168-1-50.home.arpa` 같은 이름은 백엔드 IP를 나타내며, DNS 응답은 DNSBox 프록시 주소를 가리킵니다.

- `--tls-mode=local`: 인터넷이나 포트 포워딩 없이 사설망에서 사용합니다. 클라이언트는 로컬 CA를 신뢰해야 합니다.
- `--tls-mode=acme`: 직접 제어하는 DNS 영역의 호스트명에 인증서를 발급합니다. 공개 UDP/TCP 53 DNS가 필요하며 DNS-01에는 인바운드 80 포트가 필요하지 않습니다.
- 사설 백엔드에는 명시적인 `--allowed-cidrs` 목록이 필요합니다.
- 인증서는 IP 주소 자체가 아닌 DNS 이름에 적용됩니다. 설치만으로 `dnsbox.io`를 제어할 수는 없습니다.

기존 설치 안내는 v0.5에 맞게 대체되었습니다. 전체 최신 문서는 영어로 제공됩니다.

[안내](../README.md) · [사설망과 NAT](deployment.md) · [설정](configuration.md) · [마이그레이션](migration-v0.5.md)