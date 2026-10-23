# DNSBox

DNSBox kombiniert einen autoritativen DNS-Server mit einem HTTPS-Reverse-Proxy. Namen wie `192-168-1-50.home.arpa` kodieren die Backend-IP; DNS verweist auf den DNSBox-Proxy.

- `--tls-mode=local`: privates Netzwerk ohne Internet oder Portweiterleitung. Die Clients müssen der lokalen CA vertrauen.
- `--tls-mode=acme`: Zertifikate für Hostnamen einer eigenen DNS-Zone; öffentlich erreichbares DNS über UDP und TCP 53 ist erforderlich. DNS-01 benötigt keinen eingehenden Port 80.
- Private Backends benötigen eine explizite `--allowed-cidrs`-Liste.
- Das Zertifikat gilt für den Hostnamen, nicht für die reine IP-Adresse. Eine Installation verleiht keine Kontrolle über `dnsbox.io`.

Die früheren Installationshinweise wurden für v0.5 ersetzt. Die vollständige aktuelle Dokumentation ist auf Englisch verfügbar:

[Anleitung](../README.md) · [Private Netzwerke und NAT](deployment.md) · [Konfiguration](configuration.md) · [Migration](migration-v0.5.md)