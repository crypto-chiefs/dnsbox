# DNSBox

DNSBox, yetkili DNS sunucusunu HTTPS ters proxy ile birleştirir. `192-168-1-50.home.arpa` gibi adlar arka uç IP adresini kodlar; DNS, DNSBox proxy adresini döndürür.

- `--tls-mode=local`: İnternet veya port yönlendirmesi gerektirmeyen özel ağ modu. İstemciler yerel CA sertifikasına güvenmelidir.
- `--tls-mode=acme`: kontrol ettiğiniz DNS bölgesindeki adlar için sertifikalar. UDP ve TCP 53 üzerinden herkese açık DNS gerekir; DNS-01 için gelen port 80 gerekmez.
- Özel arka uçlar için açık bir `--allowed-cidrs` listesi gerekir.
- Sertifika yalın IP adresini değil DNS adını kapsar. Kurulum `dnsbox.io` üzerinde kontrol sağlamaz.

Eski kurulum yönergeleri v0.5 için değiştirilmiştir. Güncel ve tam belgeler İngilizcedir:

[Kılavuz](../README.md) · [Özel ağlar ve NAT](deployment.md) · [Yapılandırma](configuration.md) · [Geçiş](migration-v0.5.md)