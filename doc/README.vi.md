# DNSBox

DNSBox kết hợp máy chủ DNS có thẩm quyền với proxy ngược HTTPS. Tên như `192-168-1-50.home.arpa` mã hóa IP của backend; DNS trỏ đến proxy DNSBox.

- `--tls-mode=local`: mạng riêng không cần Internet hoặc chuyển tiếp cổng. Máy khách phải tin cậy CA cục bộ.
- `--tls-mode=acme`: chứng chỉ cho tên trong vùng DNS do bạn kiểm soát; cần DNS công khai qua UDP và TCP 53. DNS-01 không cần mở cổng 80 đi vào.
- Backend riêng cần danh sách `--allowed-cidrs` rõ ràng.
- Chứng chỉ dành cho tên DNS, không phải địa chỉ IP thuần túy. Cài đặt không cấp quyền kiểm soát `dnsbox.io`.

Hướng dẫn cũ đã được thay thế cho v0.5. Tài liệu đầy đủ, cập nhật hiện có bằng tiếng Anh:

[Hướng dẫn](../README.md) · [Mạng riêng và NAT](deployment.md) · [Cấu hình](configuration.md) · [Chuyển đổi](migration-v0.5.md)