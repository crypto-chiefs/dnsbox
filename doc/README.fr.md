# DNSBox — HTTPS et Let's Encrypt pour n'importe quelle adresse IP

[🇬🇧 English](../README.md) | [🇷🇺 Русский](/doc/README.ru.md) | [🇪🇸 Español](/doc/README.es.md) | [🇩🇪 Deutsch](/doc/README.de.md) | [🇫🇷 Français](/doc/README.fr.md) | [🇨🇳 中文](/doc/README.zh.md) | [🇮🇳 हिंदी](/doc/README.hi.md) | [🇧🇷 Português](/doc/README.pt.md) | [🇹🇷 Türkçe](/doc/README.tr.md) | [🇮🇩 Bahasa Indonesia](/doc/README.id.md) | [🇻🇳 Tiếng Việt](/doc/README.vi.md) | [🇰🇷 한국어](/doc/README.ko.md)

[![Release](https://img.shields.io/github/v/release/crypto-chiefs/dnsbox)](https://github.com/crypto-chiefs/dnsbox/releases)
[![Go Version](https://img.shields.io/github/go-mod/go-version/crypto-chiefs/dnsbox)](../go.mod)

**DNSBox** est un serveur DNS open source permettant d'émettre des certificats SSL gratuits (Let's Encrypt) pour n'importe quelle adresse IP publique (IPv4 et IPv6) sans posséder de domaine. Accédez à un serveur, une API ou un appareil IoT via HTTPS directement par IP.

---

## 🔍 Fonctionnalités

- 🔐 **Certificats SSL gratuits** de Let's Encrypt pour les adresses IP
- 🌐 **Prise en charge IPv4 et IPv6**
- ⚡ **Accès HTTPS instantané** sans configuration DNS
- 🔄 **Renouvellement automatique des certificats**
- 💡 **Fonctionne sans domaine** — utilisez les sous-domaines `*.dnsbox.io`
- 🧩 **Compatible avec WebSocket, API et CI/CD**
- ⚙️ **Installation facile** via script shell
- 📦 Dépendances minimales, binaire unique, lancement sans configuration

---

## 📦 Installation

```bash
bash <(curl -sSL https://raw.githubusercontent.com/crypto-chiefs/dnsbox/main/scripts/install.sh) --ip=167.172.5.205 --domain=dnsbox.io --ns=ns3
```

Paramètres :
- `--ip` — votre adresse IP publique (obligatoire)
- `--domain` — domaine racine lié au NS (par exemple, `dnsbox.io`)
- `--ns` — sous-domaine du serveur de noms (par exemple, `ns3`)
- `--force-resolv` — désactive systemd-resolved et définit 8.8.8.8
- `--debug` — mode verbeux

---

## 🌐 Comment ça fonctionne

1. DNSBox démarre un serveur DNS qui sert dynamiquement des enregistrements A/AAAA et TXT.
2. Vous recevez un sous-domaine comme `167.172.5.205.dnsbox.io`.
3. Let's Encrypt vérifie l'enregistrement TXT `_acme-challenge` et délivre le certificat.
4. DNSBox stocke, renouvelle et fournit automatiquement le certificat SSL.

---

## 🛠 Exemple d'utilisation

Une fois installé, connectez-vous à votre serveur via HTTPS :

```bash
curl https://167.172.5.205.dnsbox.io
```

Ou testez le SSL avec OpenSSL :

```bash
openssl s_client -connect 167.172.5.205:443 -servername 167.172.5.205.dnsbox.io
```

---

## ⚙️ Détails techniques

- Langage : Go
- Librairie DNS : [miekg/dns](https://github.com/miekg/dns)
- TLS : `crypto/tls` standard
- Client ACME : support intégré (sans certbot)
- Logique dynamique : tout est traité en mémoire

---

## 🧪 Cas d'utilisation

- 🔧 Infrastructure DevOps sans domaines
- 📡 Appareils IoT avec IP publique
- 🧪 Environnements de test ou de staging
- 🚀 Déploiement rapide d'API sans DNS
- 🔐 VPN/Proxy nécessitant HTTPS

---

## 🔒 Sécurité

Tous les challenges Let's Encrypt sont servis uniquement lors de la validation IP active. Les clés privées TLS sont stockées dans `/var/lib/dnsbox/certs`.

---

## 🗺 Alternative à sslip.io et nip.io

Contrairement aux services existants :
- DNSBox est une **solution auto-hébergée open-source**
- Déployez votre propre infrastructure `*.yourdomain.tld`
- Prend en charge **IPv6**, ACME et les certificats **sans API tierce**

---

## 📜 Licence

Ce projet est sous licence MIT. Utilisation libre, fork et modification autorisés.

---

## 🔗 Liens utiles

- 🌍 Site web : https://dnsbox.io/
- 📦 Installation : [install.sh](https://github.com/crypto-chiefs/dnsbox/blob/main/scripts/install.sh)
- 📖 Documentation : en cours de rédaction

---

⭐ Si vous trouvez ce projet utile, merci de lui attribuer une ⭐ sur GitHub.
