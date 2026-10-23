# DNSBox — selbst gehostetes DNS und HTTPS für IP-basierte Hostnamen

[English](../README.md) · [Bereitstellung und private Netzwerke](deployment.md) · [Konfiguration](configuration.md) · [Hinweise zum Upgrade](migration-v0.5.md)

DNSBox verbindet einen autoritativen DNS-Server mit einem HTTPS-Reverse-Proxy. Ein Hostname wie `192-168-1-50.home.arpa` bezeichnet eine Backend-IP. DNS-Antworten verweisen auf **den DNSBox-Proxy**, der TLS terminiert und HTTP an dieses Backend weiterleitet. Unterstützt werden IPv4 mit Punkten oder Bindestrichen, IPv6 mit Bindestrichen, WebSocket-Upgrades und dauerhaft gespeicherte Zertifikate.

Es stehen zwei TLS-Modi zur Verfügung:

- **`acme`**: Zertifikate für Hostnamen in einer Domain, die Sie kontrollieren, über ACME DNS-01 (standardmäßig Let's Encrypt). Ihr autoritativer DNS-Server muss öffentlich erreichbar sein.
- **`local`**: eine dauerhaft gespeicherte lokale Zertifizierungsstelle (CA) für private Netzwerke, ohne öffentliches DNS, Internetzugang oder Portweiterleitung. Die Clients müssen der erzeugten CA vertrauen.

Die Zertifikate gelten für DNS-Hostnamen, nicht für reine IP-Adressen. Der Betrieb der Software gibt Ihnen keine Kontrolle über `dnsbox.io`. Verfügbarkeit und Konfiguration des öffentlichen Dienstes `dnsbox.io` sind unabhängig von diesem Repository.

## Schnellstart für ein privates Netzwerk

Beispiel: DNSBox-VM `192.168.1.2`, HTTP-Anwendung `192.168.1.50:80`, private Zone `home.arpa`.

Laden Sie das passende [Release-Archiv](https://github.com/crypto-chiefs/dnsbox/releases) herunter, überprüfen Sie es anhand von `checksums.txt` und starten Sie:

```bash
./dnsboxd \
  --domain=home.arpa --ip=192.168.1.2 --ns=ns1 \
  --tls-mode=local --allowed-cidrs=192.168.1.0/24 \
  --dns-listen=192.168.1.2:53 --https-listen=192.168.1.2:443 \
  --data-dir=/var/lib/dnsbox
```

Der Prozess benötigt Schreibzugriff auf das Datenverzeichnis und die Berechtigung, diese Ports zu belegen. Konfigurieren Sie Ihren LAN-Resolver so, dass er Anfragen für **die Zone `home.arpa`** an `192.168.1.2` weiterleitet. DNSBox stellt keinen allgemeinen rekursiven DNS-Dienst bereit.

Bei der ersten Zertifikatsanforderung erzeugt DNSBox `/var/lib/dnsbox/ca/root.crt` und den zugehörigen privaten Schlüssel. Übertragen Sie **nur `root.crt`** sicher auf die Clients und installieren Sie es in deren Speicher für vertrauenswürdige Zertifizierungsstellen. Einen einzelnen Aufruf können Sie so prüfen:

```bash
curl --cacert root.crt \
  --resolve 192-168-1-50.home.arpa:443:192.168.1.2 \
  https://192-168-1-50.home.arpa/
```

Sie können die CA und ein Serverzertifikat vor dem Start des Dienstes erzeugen, indem Sie dieselbe Konfiguration um `--issue=192-168-1-50.home.arpa` ergänzen. Im lokalen Modus schreibt der Befehl das Zertifikat und beendet sich, ohne Netzwerkports zu öffnen. Weitere Informationen enthält die [Anleitung für private Bereitstellungen](deployment.md).

## Installation

Installationsskript für Linux und macOS, auf die Release-Version festgelegt:

```bash
curl --fail --location \
  https://raw.githubusercontent.com/crypto-chiefs/dnsbox/v0.5.1/scripts/install.sh \
  -o install-dnsbox.sh
# Prüfen Sie das Skript und führen Sie dann Folgendes aus:
bash install-dnsbox.sh \
  --domain=home.arpa --ip=192.168.1.2 \
  --tls-mode=local --allowed-cidrs=192.168.1.0/24 \
  --dns-listen=192.168.1.2:53 --https-listen=192.168.1.2:443
```

Das Installationsskript überprüft die SHA-256-Prüfsumme des Archivs, installiert nach `~/.dnsbox` und verwendet bei einer Neuinstallation `~/.dnsbox/data` für dauerhafte Daten. Es richtet einen systemd-Dienst nur ein, wenn systemd läuft. Verwenden Sie `--no-systemd` für den manuellen Start, auch unter Calculate Linux/OpenRC:

```bash
~/.dnsbox/run-dnsbox
```

Die erzeugte Datei `~/.dnsbox/dnsbox.env` enthält die Konfiguration und bleibt bei Upgrades erhalten. Ein erneuter Aufruf des Installationsskripts aktualisiert die Programmdateien. Um Einstellungen zu ändern, bearbeiten Sie die vorhandene Umgebungsdatei. Weder die Installation noch die Deinstallation verändert den System-Resolver oder löscht Systemprotokolle. Unter Windows entpacken Sie das Archiv und starten `dnsboxd.exe` mit denselben Optionen.

## Öffentliche Zertifikate und NAT

Delegieren Sie für den ACME-Modus eine Domain oder Subdomain, **die Sie kontrollieren**, an Ihren autoritativen DNSBox-Server. Hinterlegen Sie bei Bedarf öffentliche Glue- beziehungsweise Adressdatensätze für dessen Nameserver. Leiten Sie **Port 53 sowohl über UDP als auch über TCP** an DNSBox weiter. Erlauben Sie ausgehendes HTTPS für ACME.

DNS-01 benötigt **keinen** eingehenden Port 80. Port 443 muss nur für die Clients erreichbar sein, die den HTTPS-Proxy verwenden. Das HTTP-Backend kann privat bleiben: Erlauben Sie sein Netzwerk mit `--allowed-cidrs`. Ein vollständig isoliertes Netzwerk muss stattdessen den lokalen TLS-Modus verwenden.

```bash
./dnsboxd --domain=apps.example.com --ip=203.0.113.10 --ns=ns1 \
  --acme-email=admin@example.com --data-dir=/var/lib/dnsbox
```

Ersetzen Sie die Beispielnamen und -adressen durch Ihre eigenen. `--ip` bezeichnet die Adresse, über die Clients DNSBox erreichen, nicht die Backend-Adresse. Ein IPv4-Proxy liefert A-Datensätze, ein IPv6-Proxy AAAA-Datensätze, unabhängig von der IP-Familie des Backends.

## Sicherheit und Kompatibilität

Standardmäßig sind nur öffentliche Backend-Adressen zugelassen. Eine explizite Liste mit `--allowed-cidrs` beschränkt den Zugriff auf diese Netzwerke und ermöglicht damit private Bereitstellungen. Binden Sie eine private Installation nur an LAN-Schnittstellen und betreiben Sie sie hinter Ihrer Firewall.

Die Verwaltungs-API verwendet standardmäßig `127.0.0.1:8080`. Änderungen an Datensätzen erfordern ein konfiguriertes Bearer-Token; ein leeres `--api-listen=` deaktiviert die API. Die bisherigen Endpunkte zum nicht authentifizierten Austausch von Zertifikaten wurden entfernt. v0.5 unterstützt **eine einzelne DNSBox-Instanz pro Zone**. Die Synchronisierung von Zertifikaten und Validierungsdaten zwischen mehreren Instanzen wird nicht unterstützt.

Zertifikate und private Schlüssel werden dauerhaft im Datenverzeichnis gespeichert. Sichern Sie dieses Verzeichnis auf sichere Weise. Die Dateien `certs/<hostname>.crt` und `.key` können von einem anderen Dienst wie ocserv verwendet werden. Der HTTP-Reverse-Proxy von DNSBox ist jedoch kein OpenConnect-/DTLS-Proxy. Lesen Sie die [Anleitung zum Zertifikatsexport](deployment.md#certificates-for-ocserv-or-another-service).

Lesen Sie vor einem Upgrade von v0.4 die [Migrationshinweise für v0.5](migration-v0.5.md).

## Entwicklung

Verwenden Sie die in [go.mod](../go.mod) angegebene Go-Version.

```bash
go test -race ./...
go vet ./...
bash scripts/test-install.sh
go build ./cmd/dnsboxd
```

Die Release-CI führt die Prüfungen aus, bevor sie Archive für Linux, macOS und Windows auf amd64 und arm64 veröffentlicht. [MIT-Lizenz](../LICENSE).