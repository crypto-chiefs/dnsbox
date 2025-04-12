# DNSBox — Herhangi Bir IP Adresi İçin HTTPS ve Let's Encrypt

[🇬🇧 English](../README.md) | [🇷🇺 Русский](/doc/README.ru.md) | [🇪🇸 Español](/doc/README.es.md) | [🇩🇪 Deutsch](/doc/README.de.md) | [🇫🇷 Français](/doc/README.fr.md) | [🇨🇳 中文](/doc/README.zh.md) | [🇮🇳 हिंदी](/doc/README.hi.md) | [🇧🇷 Português](/doc/README.pt.md) | [🇹🇷 Türkçe](/doc/README.tr.md) | [🇮🇩 Bahasa Indonesia](/doc/README.id.md) | [🇻🇳 Tiếng Việt](/doc/README.vi.md) | [🇰🇷 한국어](/doc/README.ko.md)

[![Release](https://img.shields.io/github/v/release/crypto-chiefs/dnsbox)](https://github.com/crypto-chiefs/dnsbox/releases)
[![Go Version](https://img.shields.io/github/go-mod/go-version/crypto-chiefs/dnsbox)](../go.mod)

**DNSBox** açık kaynaklı bir DNS sunucusudur ve herhangi bir genel IP adresi (IPv4 ve IPv6) için ücretsiz SSL sertifikaları (Let's Encrypt) oluşturmanıza olanak tanır. Bir alan adına sahip olmanıza gerek yoktur. HTTPS üzerinden doğrudan IP ile sunucularınıza, API’lere veya IoT cihazlarınıza erişin.

---

## 🔍 Özellikler

- 🔐 **Let's Encrypt'ten ücretsiz SSL sertifikaları**
- 🌐 **IPv4 ve IPv6 desteği**
- ⚡ **DNS yapılandırması olmadan anında HTTPS erişimi**
- 🔄 **Sertifikaların otomatik yenilenmesi**
- 💡 **Alan adı gerekmez** — `*.dnsbox.io` alt alan adlarını kullanabilirsiniz
- 🧩 **WebSocket, API ve CI/CD senaryolarıyla uyumlu**
- ⚙️ **Kolay kurulum** için shell betiği
- 📦 Minimum bağımlılık, tek ikili dosya, sıfır konfigürasyonla çalışır

---

## 📦 Kurulum

```bash
bash <(curl -sSL https://raw.githubusercontent.com/crypto-chiefs/dnsbox/main/scripts/install.sh) --ip=167.172.5.205 --domain=dnsbox.io --ns=ns3
```

Parametreler:
- `--ip` — genel IP adresiniz (zorunlu)
- `--domain` — NS ile ilişkili ana alan adı (örn: `dnsbox.io`)
- `--ns` — nameserver için alt alan adı (örn: `ns3`)
- `--force-resolv` — systemd-resolved devre dışı bırakılır ve 8.8.8.8 atanır
- `--debug` — ayrıntılı çıktı modu

---

## 🌐 Nasıl Çalışır?

1. DNSBox, dinamik olarak A/AAAA ve TXT kayıtları sunan bir nameserver başlatır.
2. Örneğin `167.172.5.205.dnsbox.io` gibi bir alt alan adı alırsınız.
3. Let's Encrypt `_acme-challenge` TXT kaydını doğrular ve sertifikayı verir.
4. DNSBox bu sertifikayı otomatik olarak kaydeder, yeniler ve sunar.

---

## 🛠 Kullanım Örneği

Kurulumdan sonra sunucunuza HTTPS üzerinden erişebilirsiniz:

```bash
curl https://167.172.5.205.dnsbox.io
```

OpenSSL ile SSL’i test etmek için:

```bash
openssl s_client -connect 167.172.5.205:443 -servername 167.172.5.205.dnsbox.io
```

---

## ⚙️ Teknik Detaylar

- Programlama Dili: Go
- DNS Kütüphanesi: [miekg/dns](https://github.com/miekg/dns)
- TLS: Go'nun `crypto/tls` kütüphanesi
- ACME İstemcisi: Yerleşik destek (certbot gerekmez)
- Bellekte çalışan mantık: tüm DNS istekleri ve ACME işlemleri hafızada işlenir

---

## 🧪 Kullanım Alanları

- 🔧 Alan adları olmayan DevOps altyapısı
- 📡 Genel IP’ye sahip IoT cihazları
- 🧪 Test ve staging ortamları
- 🚀 DNS yapılandırması olmadan hızlı API yayını
- 🔐 HTTPS gerektiren VPN veya proxy servisleri

---

## 🔒 Güvenlik

Tüm Let's Encrypt doğrulama istekleri yalnızca geçerli IP doğrulama sırasında işlenir. TLS özel anahtarları `/var/lib/dnsbox/certs` içinde saklanır.

---

## 🗺 sslip.io ve nip.io Alternatifi

Mevcut çözümlerden farklı olarak:
- DNSBox **kendi barındırabileceğiniz açık kaynaklı bir çözüm**
- Kendi `*.yourdomain.tld` altyapınızı kurabilirsiniz
- **IPv6**, ACME ve **harici API gerekmeden** sertifika desteği sunar

---

## 📜 Lisans

Bu proje MIT lisansı ile lisanslanmıştır. Özgürce kullanabilir, çatallayabilir ve geliştirebilirsiniz.

---

## 🔗 Faydalı Bağlantılar

- 🌍 Proje Sitesi: https://dnsbox.io/
- 📦 Kurulum Betiği: [install.sh](https://github.com/crypto-chiefs/dnsbox/blob/main/scripts/install.sh)
- 📖 Belgeler: Hazırlanıyor

---

⭐ Bu projeyi faydalı bulduysanız GitHub’da ⭐ vermeyi unutmayın!
