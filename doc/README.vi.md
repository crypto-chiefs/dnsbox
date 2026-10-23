# DNSBox — DNS và HTTPS tự lưu trữ cho tên máy chủ chứa địa chỉ IP

[English](../README.md) · [Русский](README.ru.md) · [Triển khai và mạng riêng](deployment.md) · [Cấu hình](configuration.md) · [Lưu ý khi nâng cấp](migration-v0.5.md)

DNSBox kết hợp máy chủ DNS có thẩm quyền với proxy ngược HTTPS. Tên máy chủ như `192-168-1-50.home.arpa` biểu thị địa chỉ IP của một máy chủ phía sau. Phản hồi DNS trỏ đến **proxy DNSBox**, nơi kết thúc kết nối TLS và chuyển tiếp HTTP đến máy chủ phía sau đó. DNSBox hỗ trợ IPv4 phân tách bằng dấu chấm hoặc dấu gạch nối, IPv6 phân tách bằng dấu gạch nối, nâng cấp kết nối WebSocket và lưu trữ chứng chỉ lâu dài.

Có hai chế độ TLS:

- **`acme`**: cấp chứng chỉ cho tên máy chủ thuộc miền mà bạn kiểm soát, sử dụng ACME DNS-01; mặc định là Let's Encrypt. Máy chủ DNS có thẩm quyền của bạn phải truy cập được từ Internet công cộng.
- **`local`**: cơ quan cấp chứng chỉ (CA) cục bộ được lưu trữ lâu dài cho mạng riêng, không cần DNS công cộng, kết nối Internet hay chuyển tiếp cổng. Máy khách phải được cấu hình để tin cậy CA được tạo ra.

Chứng chỉ có hiệu lực với tên máy chủ DNS, không phải địa chỉ IP thuần túy. Chạy phần mềm này không mang lại quyền kiểm soát `dnsbox.io`. Tình trạng hoạt động và cấu hình của dịch vụ công cộng `dnsbox.io` độc lập với kho mã này.

## Bắt đầu nhanh trong mạng riêng

Ví dụ: máy ảo DNSBox có địa chỉ `192.168.1.2`, ứng dụng HTTP chạy tại `192.168.1.50:80` và vùng DNS riêng là `home.arpa`.

Tải [tệp nén của bản phát hành](https://github.com/crypto-chiefs/dnsbox/releases) phù hợp, kiểm tra bằng `checksums.txt`, rồi chạy:

```bash
./dnsboxd \
  --domain=home.arpa --ip=192.168.1.2 --ns=ns1 \
  --tls-mode=local --allowed-cidrs=192.168.1.0/24 \
  --dns-listen=192.168.1.2:53 --https-listen=192.168.1.2:443 \
  --data-dir=/var/lib/dnsbox
```

Tiến trình cần có quyền ghi vào thư mục dữ liệu và quyền sử dụng các cổng này. Cấu hình trình phân giải DNS trong LAN để chuyển tiếp truy vấn cho **vùng `home.arpa`** đến `192.168.1.2`; DNSBox không cung cấp dịch vụ DNS đệ quy thông thường.

Khi nhận yêu cầu chứng chỉ đầu tiên, DNSBox tạo `/var/lib/dnsbox/ca/root.crt` và khóa riêng tương ứng. Sao chép an toàn **chỉ tệp `root.crt`** đến các máy khách và cài vào kho CA tin cậy của chúng. Để chỉ định chứng chỉ tin cậy cho một lệnh riêng lẻ, hãy thử:

```bash
curl --cacert root.crt \
  --resolve 192-168-1-50.home.arpa:443:192.168.1.2 \
  https://192-168-1-50.home.arpa/
```

Bạn có thể tạo CA và chứng chỉ máy chủ trước khi khởi động dịch vụ bằng cùng cấu hình, thêm `--issue=192-168-1-50.home.arpa`. Trong chế độ cục bộ, lệnh này ghi chứng chỉ rồi thoát mà không mở cổng lắng nghe. Xem [hướng dẫn triển khai trong mạng riêng](deployment.md).

## Cài đặt

Trình cài đặt cho Linux và macOS dưới đây được cố định theo phiên bản phát hành:

```bash
curl --fail --location \
  https://raw.githubusercontent.com/crypto-chiefs/dnsbox/v0.5.2/scripts/install.sh \
  -o install-dnsbox.sh
# Kiểm tra nội dung tập lệnh, sau đó chạy:
bash install-dnsbox.sh \
  --domain=home.arpa --ip=192.168.1.2 \
  --tls-mode=local --allowed-cidrs=192.168.1.0/24 \
  --dns-listen=192.168.1.2:53 --https-listen=192.168.1.2:443
```

Trình cài đặt xác minh tổng kiểm SHA-256 của tệp nén, cài chương trình vào `~/.dnsbox` và dùng `~/.dnsbox/data` để lưu dữ liệu lâu dài khi cài mới. Nó chỉ tạo dịch vụ systemd nếu systemd đang chạy. Dùng `--no-systemd` để khởi động thủ công, kể cả trên Calculate Linux/OpenRC:

```bash
~/.dnsbox/run-dnsbox
```

Tệp `~/.dnsbox/dnsbox.env` được tạo ra để lưu cấu hình và được giữ nguyên khi nâng cấp. Chạy lại trình cài đặt sẽ nâng cấp các tệp thực thi; muốn thay đổi thiết lập, hãy chỉnh sửa tệp môi trường hiện có. Cả trình cài đặt lẫn trình gỡ cài đặt đều không thay đổi trình phân giải DNS của hệ thống hay xóa nhật ký hệ thống. Trên Windows, giải nén rồi chạy `dnsboxd.exe` với cùng các tùy chọn.

## Chứng chỉ công cộng và NAT

Trong chế độ ACME, hãy ủy quyền miền hoặc miền con **do bạn kiểm soát** cho máy chủ DNS có thẩm quyền DNSBox của bạn. Thiết lập bản ghi glue hoặc bản ghi địa chỉ công cộng cho máy chủ tên miền đó nếu cần. Chuyển tiếp **cổng 53 của cả UDP và TCP** đến DNSBox. Cho phép kết nối HTTPS đi ra để sử dụng ACME.

DNS-01 **không** cần mở cổng 80 cho kết nối đi vào. Cổng 443 chỉ cần truy cập được từ các máy khách sử dụng proxy HTTPS. Máy chủ HTTP phía sau vẫn có thể nằm trong mạng riêng: cho phép mạng của nó bằng `--allowed-cidrs`. Mạng hoàn toàn cô lập phải sử dụng chế độ TLS cục bộ.

```bash
./dnsboxd --domain=apps.example.com --ip=203.0.113.10 --ns=ns1 \
  --acme-email=admin@example.com --data-dir=/var/lib/dnsbox
```

Thay tên và địa chỉ trong ví dụ bằng giá trị của bạn. `--ip` là địa chỉ máy khách dùng để truy cập DNSBox, không phải địa chỉ máy chủ phía sau. Proxy IPv4 trả về bản ghi A; proxy IPv6 trả về bản ghi AAAA, bất kể máy chủ phía sau dùng họ địa chỉ IP nào.

## Nhiều nút DNS và ACME

Dùng cùng một danh sách tĩnh `--nameservers` trên mọi nút. Mỗi nhãn phải là duy nhất và mỗi địa chỉ phải là IP unicast ghi trực tiếp; `--ns` và `--ip` của nút phải khớp với một mục trong danh sách. Tất cả các nút công bố cùng tập NS, địa chỉ các nút khác và máy chủ chính trong SOA. Nếu không có tùy chọn này, DNSBox chỉ công bố máy chủ tên của chính nó. Việc ủy quyền ở vùng cha, bản ghi glue và mọi địa chỉ NS được ghi đè bằng bản ghi tùy chỉnh phải nhất quán.

Để dùng ACME với nhiều nút có thẩm quyền, cấu hình `--cluster-file` trên từng nút nhằm sao chép các giá trị TXT DNS-01 tạm thời. Dùng cùng vùng DNS, chính sách truy cập backend và bản ghi tùy chỉnh trên mọi nút. Ví dụ cho nút đầu tiên:

```bash
./dnsboxd --domain=apps.example.com --ip=203.0.113.10 --ns=ns1 \
  --nameservers=ns1=203.0.113.10,ns2=203.0.113.11,ns3=203.0.113.12 \
  --cluster-file=/etc/dnsbox/cluster.json --data-dir=/var/lib/dnsbox
```

`cluster.json` cho nút đó:

```json
{
  "listen": "0.0.0.0:8443",
  "certificate": "cluster-node.crt",
  "private_key": "cluster-node.key",
  "ca_certificate": "cluster-ca.crt",
  "peers": ["https://203.0.113.11:8443", "https://203.0.113.12:8443"]
}
```

Mỗi nút phải liệt kê rõ tất cả nút còn lại bằng URL HTTPS chứa IP và cổng. Chỉ cho phép các nút này truy cập cổng cụm. Dùng CA riêng cho cụm và chứng chỉ/khóa riêng cho từng nút; SAN của chứng chỉ phải chứa IP của nút và cho phép xác thực cả máy chủ lẫn máy khách. Đường dẫn tương đối được tính từ thư mục chứa tệp JSON. Bảo vệ các tệp CA và TLS, đồng thời giữ khóa riêng của CA ngoại tuyến. Các nút xác thực lẫn nhau bằng TLS hai chiều. Chỉ các giá trị TXT tạm thời được sao chép; chứng chỉ HTTPS, khóa riêng và CA của chế độ cục bộ không được truyền đi. Các biến môi trường tương ứng là `DNSBOX_NAMESERVERS` và `DNSBOX_CLUSTER_FILE`.

## Bản ghi ALIAS ở gốc vùng DNS

Để trỏ gốc vùng DNS tới một tên của dịch vụ lưu trữ bên ngoài, thêm dòng sau vào tệp được chọn bằng `--records-file`:

```text
apps.example.com ALIAS landing.example.net.
```

Cấu hình nhà cung cấp dịch vụ lưu trữ để phục vụ miền gốc và HTTPS của bạn. DNSBox phân giải tên đích trước khi DNS sẵn sàng, cập nhật trong nền và trả lời bằng bản ghi A/AAAA trong bộ nhớ đệm, không tra cứu mạng khi xử lý từng truy vấn. Nếu lần phân giải đầu tiên thất bại, quá trình khởi động dừng lại; bộ nhớ đệm quá một giờ không được cập nhật thành công sẽ khiến truy vấn A/AAAA nhận SERVFAIL. ALIAS chỉ được dùng ở gốc vùng, phải trỏ tới tên nằm ngoài vùng và không được cùng tồn tại với A, AAAA hoặc CNAME có cùng tên. NS, SOA, TXT, MX và tên máy chủ proxy dựa trên IP vẫn hoạt động. Danh sách máy chủ tên tĩnh, sao chép TXT trong cụm và ALIAS yêu cầu v0.5.2 trở lên.

## Bảo mật và tương thích

Mặc định, chỉ cho phép các máy chủ phía sau có địa chỉ IP công cộng. Danh sách `--allowed-cidrs` được cấu hình rõ ràng sẽ giới hạn quyền truy cập vào đúng các mạng được liệt kê, cho phép triển khai trong mạng riêng. Với triển khai riêng, hãy chỉ lắng nghe trên các giao diện LAN và bảo vệ bằng tường lửa.

API quản trị mặc định sử dụng `127.0.0.1:8080`. Thay đổi bản ghi yêu cầu mã thông báo bearer đã được cấu hình; giá trị rỗng `--api-listen=` sẽ tắt API. Các điểm cuối chia sẻ chứng chỉ cũ không yêu cầu xác thực đã được loại bỏ. Mỗi nút giữ kho chứng chỉ riêng.

Chứng chỉ và khóa riêng được lưu lâu dài trong thư mục dữ liệu. Hãy sao lưu thư mục này một cách an toàn. Các tệp `certs/<hostname>.crt` và `.key` có thể dùng với dịch vụ khác như ocserv, nhưng proxy ngược HTTP của DNSBox không phải proxy OpenConnect/DTLS. Xem [hướng dẫn xuất chứng chỉ](deployment.md#certificates-for-ocserv-or-another-service).

Đọc [lưu ý chuyển đổi sang v0.5](migration-v0.5.md) trước khi nâng cấp từ v0.4.

## Phát triển

Sử dụng phiên bản Go được khai báo trong [go.mod](../go.mod).

```bash
go test -race ./...
go vet ./...
bash scripts/test-install.sh
go build ./cmd/dnsboxd
```

CI của quy trình phát hành chạy các bước kiểm tra này trước khi xuất bản tệp nén cho Linux, macOS và Windows trên amd64 và arm64. Dự án sử dụng [giấy phép MIT](../LICENSE).
