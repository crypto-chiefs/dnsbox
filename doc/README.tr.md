# DNSBox — IP tabanlı ana makine adları için kendi sunucunuzda DNS ve HTTPS

[English](../README.md) · [Kurulum ve özel ağlar](deployment.md) · [Yapılandırma](configuration.md) · [Yükseltme notları](migration-v0.5.md)

DNSBox, yetkili bir DNS sunucusunu HTTPS ters proxy ile birleştirir. `192-168-1-50.home.arpa` gibi bir ana makine adı, arka ucun IP adresini belirtir. DNS yanıtları **DNSBox proxy sunucusunu** gösterir. DNSBox, TLS bağlantısını sonlandırır ve HTTP isteklerini bu arka uca iletir. Nokta veya tire ile yazılmış IPv4, tire ile yazılmış IPv6, WebSocket bağlantı yükseltmeleri ve sertifikaların kalıcı olarak saklanması desteklenir.

İki TLS modu kullanılabilir:

- **`acme`**: kontrol ettiğiniz bir alan adındaki ana makine adları için ACME DNS-01 üzerinden sertifika alır. Varsayılan sertifika sağlayıcısı Let's Encrypt'tir. Yetkili DNS sunucunuzun İnternet'ten erişilebilir olması gerekir.
- **`local`**: özel ağlar için kalıcı bir yerel sertifika yetkilisi (CA) kullanır. Genel DNS, İnternet erişimi veya port yönlendirmesi gerekmez. İstemcilerin oluşturulan CA'ya güvenmesi gerekir.

Sertifikalar, tek başına IP adreslerini değil DNS ana makine adlarını kapsar. Yazılımı çalıştırmak `dnsbox.io` üzerinde kontrol sağlamaz. Genel `dnsbox.io` hizmetinin kullanılabilirliği ve yapılandırması bu depodan bağımsızdır.

## Özel ağda hızlı başlangıç

Örnek: DNSBox sanal makinesi `192.168.1.2`, HTTP uygulaması `192.168.1.50:80`, özel DNS bölgesi `home.arpa`.

Uygun [sürüm arşivini](https://github.com/crypto-chiefs/dnsbox/releases) indirin, `checksums.txt` ile doğrulayın ve çalıştırın:

```bash
./dnsboxd \
  --domain=home.arpa --ip=192.168.1.2 --ns=ns1 \
  --tls-mode=local --allowed-cidrs=192.168.1.0/24 \
  --dns-listen=192.168.1.2:53 --https-listen=192.168.1.2:443 \
  --data-dir=/var/lib/dnsbox
```

Sürecin veri dizinine yazma erişimi ve bu portlarda dinleme izni olmalıdır. LAN DNS çözümleyicinizi **`home.arpa` bölgesine** ait sorguları `192.168.1.2` adresine yönlendirecek şekilde yapılandırın. DNSBox genel amaçlı özyinelemeli DNS hizmeti sağlamaz.

İlk sertifika isteğinde DNSBox, `/var/lib/dnsbox/ca/root.crt` dosyasını ve ilgili özel anahtarı oluşturur. İstemcilere güvenli bir şekilde **yalnızca `root.crt` dosyasını** kopyalayın ve dosyayı güvenilen sertifika yetkilileri deposuna yükleyin. Tek bir isteği sınamak için şu komutu kullanın:

```bash
curl --cacert root.crt \
  --resolve 192-168-1-50.home.arpa:443:192.168.1.2 \
  https://192-168-1-50.home.arpa/
```

Hizmeti başlatmadan önce aynı yapılandırmaya `--issue=192-168-1-50.home.arpa` ekleyerek CA'yı ve bir sunucu sertifikasını oluşturabilirsiniz. Yerel modda bu komut sertifikayı kaydeder ve dinleme portu açmadan sonlanır. Ayrıntılar için [özel ağ kurulum kılavuzuna](deployment.md) bakın.

## Kurulum

Belirli sürüme sabitlenmiş Linux ve macOS kurulum betiği:

```bash
curl --fail --location \
  https://raw.githubusercontent.com/crypto-chiefs/dnsbox/v0.5.2/scripts/install.sh \
  -o install-dnsbox.sh
# Betiği inceleyin, ardından çalıştırın:
bash install-dnsbox.sh \
  --domain=home.arpa --ip=192.168.1.2 \
  --tls-mode=local --allowed-cidrs=192.168.1.0/24 \
  --dns-listen=192.168.1.2:53 --https-listen=192.168.1.2:443
```

Kurulum betiği arşivin SHA-256 sağlama toplamını doğrular, programı `~/.dnsbox` dizinine kurar ve yeni kurulumlarda kalıcı veriler için `~/.dnsbox/data` dizinini kullanır. Yalnızca systemd çalışıyorsa bir systemd hizmeti oluşturur. Calculate Linux/OpenRC dahil, elle başlatmak için `--no-systemd` kullanın:

```bash
~/.dnsbox/run-dnsbox
```

Oluşturulan `~/.dnsbox/dnsbox.env` dosyası yapılandırmayı saklar ve yükseltmelerde korunur. Kurulum betiğini yeniden çalıştırmak program dosyalarını günceller. Ayarları değiştirmek için mevcut ortam dosyasını düzenleyin. Kurulum ve kaldırma betikleri sistemin DNS çözümleyicisini değiştirmez veya sistem günlüklerini silmez. Windows'ta arşivi çıkarın ve `dnsboxd.exe` dosyasını aynı seçeneklerle çalıştırın.

## Genel sertifikalar ve NAT

ACME modu için **kontrol ettiğiniz** bir alan adını veya alt alan adını yetkili DNSBox sunucunuza devredin. Gerektiğinde ad sunucusu için genel glue veya adres kayıtlarını ekleyin. **Hem UDP hem TCP 53 portunu** DNSBox'a yönlendirin. ACME için dışarıya HTTPS bağlantılarına izin verin.

DNS-01 için **gelen 80 portunu açmak gerekmez**. 443 portunun yalnızca HTTPS proxy kullanan istemciler tarafından erişilebilir olması yeterlidir. HTTP arka ucu özel ağda kalabilir; `--allowed-cidrs` ile bu ağa izin verin. Tamamen yalıtılmış bir ağda yerel TLS modu kullanılmalıdır.

```bash
./dnsboxd --domain=apps.example.com --ip=203.0.113.10 --ns=ns1 \
  --acme-email=admin@example.com --data-dir=/var/lib/dnsbox
```

Örnek adları ve adresleri kendi değerlerinizle değiştirin. `--ip`, arka uç adresini değil, istemcilerin DNSBox'a ulaşmak için kullandığı adresi belirtir. Arka ucun IP ailesinden bağımsız olarak IPv4 proxy A kayıtları, IPv6 proxy ise AAAA kayıtları döndürür.

## Birden fazla DNS düğümü ve ACME

Her düğümde aynı statik `--nameservers` listesini kullanın. Her etiket benzersiz, her adres ise doğrudan yazılmış bir unicast IP adresi olmalıdır. Yerel `--ns` ve `--ip` değerleri listedeki bir girişle eşleşmelidir. Tüm düğümler aynı NS kümesini, düğüm adreslerini ve SOA birincil sunucusunu yayımlar. Bu seçenek verilmezse DNSBox yalnızca kendi ad sunucusunu yayımlar. Üst bölgedeki yetki devrini, glue kayıtlarını ve özel NS adresi değişikliklerini birbiriyle tutarlı tutun.

Birden fazla yetkili düğümle ACME kullanmak için her düğümde `--cluster-file` yapılandırarak geçici DNS-01 TXT değerlerini çoğaltın. Tüm düğümlerde aynı bölgeyi, arka uç erişim kurallarını ve özel kayıtları kullanın. İlk düğüm için örnek:

```bash
./dnsboxd --domain=apps.example.com --ip=203.0.113.10 --ns=ns1 \
  --nameservers=ns1=203.0.113.10,ns2=203.0.113.11,ns3=203.0.113.12 \
  --cluster-file=/etc/dnsbox/cluster.json --data-dir=/var/lib/dnsbox
```

Bu düğümün `cluster.json` dosyası:

```json
{
  "listen": "0.0.0.0:8443",
  "certificate": "cluster-node.crt",
  "private_key": "cluster-node.key",
  "ca_certificate": "cluster-ca.crt",
  "peers": ["https://203.0.113.11:8443", "https://203.0.113.12:8443"]
}
```

Her düğüm, diğer tüm düğümleri IP ve port içeren açık bir HTTPS URL'siyle listeler. Küme portuna erişimi bu düğümlerle sınırlayın. Kümeye özel bir CA ve her düğüm için ayrı bir sertifika ile anahtar kullanın. Sertifika, SAN alanında düğümün IP adresini içermeli ve hem sunucu hem istemci kimlik doğrulamasına izin vermelidir. Dosya yolları JSON dosyasına göredir. CA ve TLS dosyalarını koruyun; CA'nın özel anahtarını çevrimdışı tutun. Karşılıklı TLS, düğümlerin kimliğini doğrular. Yalnızca geçici TXT değerleri çoğaltılır; HTTPS sertifikaları, özel anahtarlar veya yerel modun CA'sı asla paylaşılmaz. İlgili ortam değişkenleri `DNSBOX_NAMESERVERS` ve `DNSBOX_CLUSTER_FILE` şeklindedir.

## Bölge kökünde ALIAS kayıtları

Bölge kökünü harici bir barındırma hizmetinin adına yönlendirmek için `--records-file` ile seçilen dosyaya şunu ekleyin:

```text
apps.example.com ALIAS landing.example.net.
```

Barındırma sağlayıcısını, kök alan adınıza ve HTTPS'ye hizmet verecek şekilde yapılandırın. DNSBox, DNS hizmeti hazır olmadan önce hedefi çözer, arka planda günceller ve sorgu işleme sırasında yeni bir çözümleme yapmadan önbellekteki A/AAAA kayıtlarıyla yanıt verir. İlk çözümleme başarısız olursa başlatma durur. Önbellek bir saatten eskiyse A/AAAA sorgularına SERVFAIL döndürülür. ALIAS yalnızca bölge kökünde kullanılabilir, bölgenin dışındaki bir adı hedeflemeli ve aynı yerde A, AAAA veya CNAME ile birlikte bulunmamalıdır. NS, SOA, TXT, MX ve IP tabanlı proxy ana makine adları kullanılabilir olmaya devam eder. Statik ad sunucusu listeleri, kümede TXT çoğaltma ve ALIAS için v0.5.2 veya üzeri gerekir.

## Güvenlik ve uyumluluk

Varsayılan olarak yalnızca genel arka uç adreslerine izin verilir. Açıkça belirtilen bir `--allowed-cidrs` listesi, erişimi bu ağlarla sınırlar ve özel ağ kurulumlarını mümkün kılar. Özel ağ kurulumunda dinleme adreslerini LAN arayüzlerine bağlayın ve hizmeti güvenlik duvarınızın arkasında tutun.

Yönetim API'si varsayılan olarak `127.0.0.1:8080` adresini kullanır. Kayıt değişiklikleri için yapılandırılmış bir Bearer belirteci gerekir. Boş `--api-listen=` değeri API'yi devre dışı bırakır. Kimlik doğrulaması olmadan sertifika paylaşan eski uç noktalar kaldırılmıştır. Her düğüm kendi sertifika deposunu tutar.

Sertifikalar ve özel anahtarlar veri dizininde kalıcı olarak saklanır. Bu dizini güvenli bir şekilde yedekleyin. `certs/<hostname>.crt` ve `.key` dosyaları ocserv gibi başka bir hizmet tarafından kullanılabilir. Ancak DNSBox'ın HTTP ters proxy hizmeti, OpenConnect/DTLS proxy değildir. [Sertifika dışa aktarma yönergelerine](deployment.md#certificates-for-ocserv-or-another-service) bakın.

v0.4 sürümünden yükseltmeden önce [v0.5 geçiş notlarını](migration-v0.5.md) okuyun.

## Geliştirme

[go.mod](../go.mod) dosyasında belirtilen Go sürümünü kullanın.

```bash
go test -race ./...
go vet ./...
bash scripts/test-install.sh
go build ./cmd/dnsboxd
```

Sürüm yayımlama CI iş akışı, amd64 ve arm64 için Linux, macOS ve Windows arşivlerini yayımlamadan önce kontrolleri çalıştırır. [MIT lisansı](../LICENSE).