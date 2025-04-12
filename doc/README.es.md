# DNSBox — HTTPS y Let's Encrypt para cualquier dirección IP

[🇬🇧 English](../README.md) | [🇷🇺 Русский](/doc/README.ru.md) | [🇪🇸 Español](/doc/README.es.md) | [🇩🇪 Deutsch](/doc/README.de.md) | [🇫🇷 Français](/doc/README.fr.md) | [🇨🇳 中文](/doc/README.zh.md) | [🇮🇳 हिंदी](/doc/README.hi.md) | [🇧🇷 Português](/doc/README.pt.md) | [🇹🇷 Türkçe](/doc/README.tr.md) | [🇮🇩 Bahasa Indonesia](/doc/README.id.md) | [🇻🇳 Tiếng Việt](/doc/README.vi.md) | [🇰🇷 한국어](/doc/README.ko.md)

[![Release](https://img.shields.io/github/v/release/crypto-chiefs/dnsbox)](https://github.com/crypto-chiefs/dnsbox/releases)
[![Go Version](https://img.shields.io/github/go-mod/go-version/crypto-chiefs/dnsbox)](../go.mod)

**DNSBox** es un servidor DNS de código abierto que permite emitir certificados SSL gratuitos (Let's Encrypt) para cualquier dirección IP pública (IPv4 e IPv6) sin necesidad de poseer un dominio. Obtenga acceso HTTPS a su servidor, API o dispositivo IoT directamente por IP.

---

## 🔍 Características

- 🔐 **Certificados SSL gratuitos** de Let's Encrypt para direcciones IP
- 🌐 **Compatible con IPv4 e IPv6**
- ⚡ **Acceso HTTPS instantáneo** sin configuración DNS
- 🔄 **Renovación automática de certificados**
- 💡 **Funciona incluso sin dominio** — use subdominios `*.dnsbox.io`
- 🧩 **Compatible con WebSocket, API y escenarios CI/CD**
- ⚙️ **Instalador ligero** mediante script shell
- 📦 Dependencias mínimas, binario único, sin configuración

---

## 📦 Instalación

```bash
bash <(curl -sSL https://raw.githubusercontent.com/crypto-chiefs/dnsbox/main/scripts/install.sh) --ip=167.172.5.205 --domain=dnsbox.io --ns=ns3
```

Parámetros:
- `--ip` — su dirección IP pública (obligatorio)
- `--domain` — dominio raíz vinculado al NS (por ejemplo, `dnsbox.io`)
- `--ns` — subdominio del servidor de nombres (por ejemplo, `ns3`)
- `--force-resolv` — desactiva systemd-resolved y configura 8.8.8.8
- `--debug` — modo detallado

---

## 🌐 Cómo funciona

1. DNSBox inicia un servidor de nombres que responde con registros A/AAAA y TXT dinámicamente.
2. Obtiene un subdominio como `167.172.5.205.dnsbox.io`.
3. Let's Encrypt verifica el registro TXT `_acme-challenge` y emite el certificado.
4. DNSBox guarda, renueva y sirve automáticamente el certificado SSL.

---

## 🛠 Ejemplo de uso

Una vez instalado, puede conectarse a su servidor mediante HTTPS:

```bash
curl https://167.172.5.205.dnsbox.io
```

O probar el certificado SSL con OpenSSL:

```bash
openssl s_client -connect 167.172.5.205:443 -servername 167.172.5.205.dnsbox.io
```

---

## ⚙️ Tecnologías utilizadas

- Lenguaje: Go
- Librería DNS: [miekg/dns](https://github.com/miekg/dns)
- TLS: `crypto/tls` estándar
- Cliente ACME: soporte ACME integrado (sin certbot)
- Lógica dinámica: todos los desafíos DNS se manejan en memoria

---

## 🧪 Casos de uso

- 🔧 Infraestructura DevOps sin dominios
- 📡 Dispositivos IoT con IP pública
- 🧪 Entornos de prueba o staging
- 🚀 Despliegue rápido de API sin configuración DNS
- 🔐 Servicios VPN/Proxy que requieren HTTPS

---

## 🔒 Seguridad

Todos los desafíos de Let's Encrypt solo se sirven durante validaciones activas. Las claves privadas TLS se almacenan en `/var/lib/dnsbox/certs`.

---

## 🗺 Alternativa a sslip.io y nip.io

A diferencia de otros servicios:
- DNSBox es una **solución autoalojada de código abierto**
- Puede desplegar su propio `*.yourdomain.tld`
- Soporte completo para **IPv6**, ACME y certificados **sin APIs externas**

---

## 📜 Licencia

Este proyecto está licenciado bajo la Licencia MIT. Úselo libremente, fórrquelo, mejórelo.

---

## 🔗 Enlaces útiles

- 🌍 Sitio web del proyecto: https://dnsbox.io/
- 📦 Instalador: [install.sh](https://github.com/crypto-chiefs/dnsbox/blob/main/scripts/install.sh)
- 📖 Documentación: en desarrollo

---

⭐ Si encuentra útil este proyecto, no olvide darle una estrella en GitHub.
