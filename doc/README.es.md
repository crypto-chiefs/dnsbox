# DNSBox

DNSBox combina un servidor DNS autoritativo con un proxy inverso HTTPS. Los nombres como `192-168-1-50.home.arpa` codifican la IP del backend; DNS apunta al proxy DNSBox.

- `--tls-mode=local`: red privada sin Internet ni redirección de puertos. Los clientes deben confiar en la CA local.
- `--tls-mode=acme`: certificados para nombres de una zona DNS propia; requiere DNS público por UDP y TCP 53. DNS-01 no necesita el puerto 80 de entrada.
- Los backends privados requieren una lista explícita `--allowed-cidrs`.
- El certificado identifica el nombre DNS, no la IP sin dominio. Instalar DNSBox no concede control sobre `dnsbox.io`.

Las instrucciones anteriores se han sustituido para v0.5. La documentación completa y actualizada está en inglés:

[Guía](../README.md) · [Redes privadas y NAT](deployment.md) · [Configuración](configuration.md) · [Migración](migration-v0.5.md)