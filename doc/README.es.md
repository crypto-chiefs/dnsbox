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
  https://raw.githubusercontent.com/crypto-chiefs/dnsbox/v0.5.2/scripts/install.sh \
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

## Varios nodos DNS y ACME

Utiliza la misma lista estática `--nameservers` en todos los nodos. Cada etiqueta debe ser única y cada dirección debe ser una IP unicast literal; los valores locales de `--ns` y `--ip` deben coincidir con una entrada. Todos los nodos publican el mismo conjunto de registros NS, las mismas direcciones de los nodos y el mismo servidor primario en el registro SOA. Sin esta opción, DNSBox solo publica su propio servidor de nombres. Mantén coherentes la delegación en la zona superior, los registros glue y cualquier dirección NS personalizada que sustituya a la predeterminada.

Para utilizar ACME con varios nodos autoritativos, configura `--cluster-file` en cada uno para replicar los valores TXT temporales de DNS-01. Utiliza la misma zona, las mismas reglas de acceso a backends y los mismos registros personalizados en todos los nodos. Ejemplo para el primer nodo:

```bash
./dnsboxd --domain=apps.example.com --ip=203.0.113.10 --ns=ns1 \
  --nameservers=ns1=203.0.113.10,ns2=203.0.113.11,ns3=203.0.113.12 \
  --cluster-file=/etc/dnsbox/cluster.json --data-dir=/var/lib/dnsbox
```

Archivo `cluster.json` de ese nodo:

```json
{
  "listen": "0.0.0.0:8443",
  "certificate": "cluster-node.crt",
  "private_key": "cluster-node.key",
  "ca_certificate": "cluster-ca.crt",
  "peers": ["https://203.0.113.11:8443", "https://203.0.113.12:8443"]
}
```

Cada nodo enumera todos los demás mediante una URL HTTPS explícita con IP y puerto. Restringe el acceso al puerto del clúster a esos nodos. Utiliza una CA dedicada al clúster y un certificado y una clave distintos para cada nodo. El certificado debe incluir la IP del nodo en el SAN y permitir la autenticación tanto de servidor como de cliente. Las rutas son relativas al archivo JSON. Protege los archivos de la CA y de TLS, y guarda la clave privada de la CA sin conexión. TLS mutuo autentica a los nodos; solo se replican los valores TXT temporales, nunca los certificados HTTPS, las claves privadas ni la CA del modo local. Las variables de entorno correspondientes son `DNSBOX_NAMESERVERS` y `DNSBOX_CLUSTER_FILE`.

## Registros ALIAS en el ápice de la zona

Para apuntar el ápice de la zona a un nombre de alojamiento externo, añade lo siguiente al archivo seleccionado mediante `--records-file`:

```text
apps.example.com ALIAS landing.example.net.
```

Configura ese proveedor de alojamiento para que sirva tu dominio raíz y HTTPS. DNSBox resuelve el destino antes de que el servicio DNS esté listo, lo actualiza en segundo plano y responde con los registros A/AAAA de la caché sin resolver nombres durante el procesamiento de las consultas. Un fallo en la resolución inicial impide el inicio; si la caché tiene más de una hora, las consultas A/AAAA reciben SERVFAIL. ALIAS solo se permite en el ápice, debe apuntar a un nombre ajeno a la zona y no puede coexistir allí con A, AAAA ni CNAME. Los registros NS, SOA, TXT, MX y los nombres del proxy basados en IP siguen disponibles. Las listas estáticas de servidores de nombres, la replicación de TXT en clúster y ALIAS requieren v0.5.2 o una versión posterior.

## Seguridad y compatibilidad

De forma predeterminada, solo se permiten direcciones públicas de backend. Una lista explícita `--allowed-cidrs` restringe el acceso a esas redes y permite los despliegues privados. Mantén las instalaciones privadas escuchando en interfaces de LAN y protegidas por tu cortafuegos.

La API de administración escucha de forma predeterminada en `127.0.0.1:8080`. Las modificaciones de registros requieren un token de portador configurado; un valor vacío `--api-listen=` desactiva la API. Se han eliminado los antiguos puntos de acceso para compartir certificados sin autenticación. Cada nodo conserva su propio almacén de certificados.

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