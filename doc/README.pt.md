# DNSBox

O DNSBox combina um servidor DNS autoritativo com um proxy reverso HTTPS. Nomes como `192-168-1-50.home.arpa` codificam o IP do backend; o DNS aponta para o proxy DNSBox.

- `--tls-mode=local`: rede privada sem Internet ou encaminhamento de portas. Os clientes precisam confiar na CA local.
- `--tls-mode=acme`: certificados para nomes de uma zona DNS sob seu controle; exige DNS público por UDP e TCP 53. DNS-01 não exige a porta 80 de entrada.
- Backends privados exigem uma lista explícita `--allowed-cidrs`.
- O certificado identifica o nome DNS, não o IP isolado. Instalar o DNSBox não concede controle sobre `dnsbox.io`.

As instruções anteriores foram substituídas para a v0.5. A documentação completa e atual está em inglês:

[Guia](../README.md) · [Redes privadas e NAT](deployment.md) · [Configuração](configuration.md) · [Migração](migration-v0.5.md)