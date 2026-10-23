# DNSBox — DNS y HTTPS autoalojados para nombres de host basados en IP

[English](../README.md) · [Despliegue y redes privadas](deployment.md) · [Configuración](configuration.md) · [Notas de actualización](migration-v0.5.md)

DNSBox combina un servidor DNS autoritativo con un proxy inverso HTTPS. Un nombre de host como `192-168-1-50.home.arpa` identifica la IP de un backend. Las respuestas DNS apuntan **al proxy DNSBox**, que termina TLS y reenvía HTTP a ese backend. Admite IPv4 con puntos o guiones, IPv6 con guiones, conexiones WebSocket mediante actualización de protocolo y almacenamiento persistente de certificados.

Hay dos modos TLS disponibles:

- **`acme`**: certificados para nombres de host de un dominio que controlas, mediante ACME DNS-01 (Let's Encrypt de forma predeterminada). Tu DNS autoritativo debe ser accesible públicamente.
- **`local`**: una autoridad de certificación (CA) local y persistente para redes privadas, sin DNS público, acceso a Internet ni redirección de puertos. Los clientes deben confiar en la CA generada.

Los certificados cubren nombres de host DNS, no direcciones IP sin dominio. Ejecutar el software no otorga control sobre `dnsbox.io`. La disponibilidad y la configuración del servicio público `dnsbox.io` son independientes de este repositorio.

## Inicio rápido en una red privada

Ejemplo: máquina virtual DNSBox `192.168.1.2`, aplicación HTTP `192.168.1.50:80`, zona privada `home.arpa`.

Descarga el [archivo de la versión](https://github.com/crypto-chiefs/dnsbox/releases) correspondiente, verifícalo con `checksums.txt` y ejecuta:

```bash
./dnsboxd \
  --domain=home.arpa --ip=192.168.1.2 --ns=ns1 \
  --tls-mode=local --allowed-cidrs=192.168.1.0/24 \
  --dns-listen=192.168.1.2:53 --https-listen=192.168.1.2:443 \
  --data-dir=/var/lib/dnsbox
```

El proceso necesita acceso de escritura al directorio de datos y permiso para escuchar en estos puertos. Configura el resolvedor de tu LAN para reenviar **la zona `home.arpa`** a `192.168.1.2`; DNSBox no proporciona un servicio DNS recursivo de uso general.

En la primera solicitud de un certificado, DNSBox crea `/var/lib/dnsbox/ca/root.crt` y su clave privada. Copia de forma segura **solo `root.crt`** a los clientes e instálalo en su almacén de CA de confianza. Para probar una sola solicitud, utiliza:

```bash
curl --cacert root.crt \
  --resolve 192-168-1-50.home.arpa:443:192.168.1.2 \
  https://192-168-1-50.home.arpa/
```

Puedes crear la CA y un certificado de servidor antes de iniciar el servicio usando la misma configuración y añadiendo `--issue=192-168-1-50.home.arpa`. En modo local, este comando escribe el certificado y termina sin abrir puertos de escucha. Consulta la [guía de despliegue privado](deployment.md).

## Instalación

Instalador para Linux y macOS, fijado a la versión publicada:

```bash
curl --fail --location \
  https://raw.githubusercontent.com/crypto-chiefs/dnsbox/v0.5.1/scripts/install.sh \
  -o install-dnsbox.sh
# Revisa el script y después ejecuta:
bash install-dnsbox.sh \
  --domain=home.arpa --ip=192.168.1.2 \
  --tls-mode=local --allowed-cidrs=192.168.1.0/24 \
  --dns-listen=192.168.1.2:53 --https-listen=192.168.1.2:443
```

El instalador verifica la suma SHA-256 del archivo, instala en `~/.dnsbox` y utiliza `~/.dnsbox/data` para los datos persistentes en las instalaciones nuevas. Solo crea un servicio de systemd cuando systemd está en ejecución. Utiliza `--no-systemd` para iniciar manualmente, también en Calculate Linux/OpenRC:

```bash
~/.dnsbox/run-dnsbox
```

El archivo generado `~/.dnsbox/dnsbox.env` guarda la configuración y se conserva durante las actualizaciones. Volver a ejecutar el instalador actualiza los binarios; para cambiar ajustes, edita el archivo de entorno existente. Ni el instalador ni el desinstalador modifican el resolvedor del sistema ni eliminan registros del sistema. En Windows, extrae el archivo y ejecuta `dnsboxd.exe` con las mismas opciones.

## Certificados públicos y NAT

Para el modo ACME, delega un dominio o subdominio **que controles** en tu servidor autoritativo DNSBox. Añade los registros públicos de enlace —glue— o de dirección que necesite su servidor de nombres. Redirige **el puerto 53 tanto UDP como TCP** a DNSBox. Permite las conexiones HTTPS salientes para ACME.

DNS-01 **no** necesita el puerto 80 de entrada. El puerto 443 solo debe ser accesible para los clientes que utilizan el proxy HTTPS. El backend HTTP puede permanecer en la red privada: permite su red con `--allowed-cidrs`. Una red completamente aislada debe utilizar el modo TLS local.

```bash
./dnsboxd --domain=apps.example.com --ip=203.0.113.10 --ns=ns1 \
  --acme-email=admin@example.com --data-dir=/var/lib/dnsbox
```

Sustituye los nombres y las direcciones de ejemplo por los tuyos. `--ip` es la dirección que usan los clientes para acceder a DNSBox, no la del backend. Un proxy IPv4 devuelve registros A y un proxy IPv6 devuelve registros AAAA, independientemente de la familia IP del backend.

## Seguridad y compatibilidad

De forma predeterminada, solo se permiten direcciones públicas de backend. Una lista explícita `--allowed-cidrs` restringe el acceso a esas redes y permite los despliegues privados. Mantén las instalaciones privadas escuchando en interfaces de LAN y protegidas por tu cortafuegos.

La API de administración escucha de forma predeterminada en `127.0.0.1:8080`. Las modificaciones de registros requieren un token de portador configurado; un valor vacío `--api-listen=` desactiva la API. Se han eliminado los antiguos puntos de acceso para compartir certificados sin autenticación. La versión v0.5 admite **una única instancia de DNSBox por zona**; no admite la sincronización de certificados ni de datos de validación entre varios nodos.

Los certificados y las claves privadas se guardan de forma persistente en el directorio de datos. Haz una copia de seguridad de ese directorio y protégela. Otro servicio, como ocserv, puede utilizar los archivos `certs/<hostname>.crt` y `.key`, pero el proxy inverso HTTP de DNSBox no es un proxy OpenConnect/DTLS. Consulta las [instrucciones para exportar certificados](deployment.md#certificates-for-ocserv-or-another-service).

Antes de actualizar desde v0.4, lee las [notas de migración a v0.5](migration-v0.5.md).

## Desarrollo

Utiliza la versión de Go indicada en [go.mod](../go.mod).

```bash
go test -race ./...
go vet ./...
bash scripts/test-install.sh
go build ./cmd/dnsboxd
```

La integración continua de publicación ejecuta las comprobaciones antes de publicar archivos para Linux, macOS y Windows en amd64 y arm64. [Licencia MIT](../LICENSE).