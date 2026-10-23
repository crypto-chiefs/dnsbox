# DNSBox — DNS et HTTPS auto-hébergés pour des noms d’hôte basés sur une IP

[English](../README.md) · [Déploiement et réseaux privés](deployment.md) · [Configuration](configuration.md) · [Notes de mise à niveau](migration-v0.5.md)

DNSBox associe un serveur DNS faisant autorité à un proxy inverse HTTPS. Un nom d’hôte tel que `192-168-1-50.home.arpa` identifie l’adresse IP d’un serveur applicatif. Les réponses DNS pointent vers **le proxy DNSBox**, qui termine la connexion TLS et transmet les requêtes HTTP à ce serveur. DNSBox prend en charge les adresses IPv4 avec des points ou des tirets, les adresses IPv6 avec des tirets, les mises à niveau de connexion WebSocket et le stockage persistant des certificats.

Deux modes TLS sont disponibles :

- **`acme`** : des certificats pour les noms d’hôte d’un domaine que vous contrôlez, via ACME DNS-01 (Let's Encrypt par défaut). Votre DNS faisant autorité doit être accessible publiquement.
- **`local`** : une autorité de certification (CA) locale et persistante pour les réseaux privés, sans DNS public, accès à Internet ni redirection de ports. Les clients doivent faire confiance à l’autorité créée.

Les certificats couvrent les noms d’hôte DNS, pas les adresses IP seules. L’exécution du logiciel ne donne aucun contrôle sur `dnsbox.io`. La disponibilité et la configuration du service public `dnsbox.io` sont indépendantes de ce dépôt.

## Démarrage rapide dans un réseau privé

Exemple : machine virtuelle DNSBox `192.168.1.2`, application HTTP `192.168.1.50:80`, zone privée `home.arpa`.

Téléchargez l’[archive de version](https://github.com/crypto-chiefs/dnsbox/releases) appropriée, vérifiez-la à l’aide de `checksums.txt`, puis exécutez :

```bash
./dnsboxd \
  --domain=home.arpa --ip=192.168.1.2 --ns=ns1 \
  --tls-mode=local --allowed-cidrs=192.168.1.0/24 \
  --dns-listen=192.168.1.2:53 --https-listen=192.168.1.2:443 \
  --data-dir=/var/lib/dnsbox
```

Le processus doit disposer d’un accès en écriture au répertoire de données et de l’autorisation d’écouter sur ces ports. Configurez le résolveur de votre réseau local pour transférer les requêtes de **la zone `home.arpa`** vers `192.168.1.2` ; DNSBox ne fournit pas de service DNS récursif généraliste.

Lors de la première demande de certificat, DNSBox crée `/var/lib/dnsbox/ca/root.crt` et sa clé privée. Transférez de manière sécurisée **uniquement `root.crt`** vers les clients et installez-le dans leur magasin d’autorités de certification de confiance. Pour tester une requête isolée, utilisez :

```bash
curl --cacert root.crt \
  --resolve 192-168-1-50.home.arpa:443:192.168.1.2 \
  https://192-168-1-50.home.arpa/
```

Vous pouvez créer l’autorité de certification et un certificat serveur avant de démarrer le service, avec la même configuration et l’option supplémentaire `--issue=192-168-1-50.home.arpa`. En mode local, cette commande enregistre le certificat et se termine sans ouvrir de ports d’écoute. Consultez le [guide de déploiement privé](deployment.md).

## Installation

Script d’installation pour Linux et macOS, associé à une version précise :

```bash
curl --fail --location \
  https://raw.githubusercontent.com/crypto-chiefs/dnsbox/v0.5.2/scripts/install.sh \
  -o install-dnsbox.sh
# Examinez le script, puis exécutez :
bash install-dnsbox.sh \
  --domain=home.arpa --ip=192.168.1.2 \
  --tls-mode=local --allowed-cidrs=192.168.1.0/24 \
  --dns-listen=192.168.1.2:53 --https-listen=192.168.1.2:443
```

Le script vérifie la somme de contrôle SHA-256 de l’archive, installe le programme dans `~/.dnsbox` et utilise `~/.dnsbox/data` pour les données persistantes lors d’une nouvelle installation. Il crée un service systemd uniquement lorsque systemd est en cours d’exécution. Utilisez `--no-systemd` pour un démarrage manuel, notamment avec Calculate Linux/OpenRC :

```bash
~/.dnsbox/run-dnsbox
```

Le fichier généré `~/.dnsbox/dnsbox.env` contient la configuration et est conservé lors des mises à niveau. Une nouvelle exécution du script met à jour les binaires ; pour modifier les paramètres, éditez le fichier d’environnement existant. Ni l’installation ni la désinstallation ne modifie le résolveur du système ou ne supprime les journaux système. Sous Windows, extrayez l’archive et lancez `dnsboxd.exe` avec les mêmes options.

## Certificats publics et NAT

Pour le mode ACME, déléguez un domaine ou un sous-domaine **que vous contrôlez** à votre serveur DNSBox faisant autorité. Fournissez au besoin des enregistrements publics de liaison — « glue » — ou d’adresse pour son serveur de noms. Redirigez **le port 53 en UDP et en TCP** vers DNSBox. Autorisez les connexions HTTPS sortantes pour ACME.

DNS-01 **ne nécessite pas** l’ouverture du port entrant 80. Le port 443 doit seulement être accessible aux clients qui utilisent le proxy HTTPS. Le serveur HTTP applicatif peut rester privé : autorisez son réseau avec `--allowed-cidrs`. Un réseau entièrement isolé doit utiliser le mode TLS local.

```bash
./dnsboxd --domain=apps.example.com --ip=203.0.113.10 --ns=ns1 \
  --acme-email=admin@example.com --data-dir=/var/lib/dnsbox
```

Remplacez les noms et adresses d’exemple par les vôtres. `--ip` désigne l’adresse utilisée par les clients pour joindre DNSBox, et non celle du serveur applicatif. Un proxy IPv4 renvoie des enregistrements A ; un proxy IPv6 renvoie des enregistrements AAAA, quelle que soit la famille IP du serveur applicatif.

## Plusieurs nœuds DNS et ACME

Utilisez la même liste statique `--nameservers` sur chaque nœud. Chaque libellé doit être unique et chaque adresse doit être une IP unicast littérale ; les valeurs locales de `--ns` et `--ip` doivent correspondre à une entrée. Tous les nœuds publient le même ensemble de NS, les mêmes adresses des nœuds et le même serveur primaire dans le SOA. Sans cette option, DNSBox publie uniquement son propre serveur de noms. Assurez-vous que la délégation dans la zone parente, les enregistrements glue et les éventuelles adresses NS personnalisées restent cohérents.

Pour utiliser ACME avec plusieurs nœuds faisant autorité, configurez `--cluster-file` sur chaque nœud afin de répliquer les valeurs TXT temporaires de DNS-01. Utilisez la même zone, les mêmes règles d’accès aux serveurs applicatifs et les mêmes enregistrements personnalisés sur tous les nœuds. Exemple pour le premier nœud :

```bash
./dnsboxd --domain=apps.example.com --ip=203.0.113.10 --ns=ns1 \
  --nameservers=ns1=203.0.113.10,ns2=203.0.113.11,ns3=203.0.113.12 \
  --cluster-file=/etc/dnsbox/cluster.json --data-dir=/var/lib/dnsbox
```

Fichier `cluster.json` de ce nœud :

```json
{
  "listen": "0.0.0.0:8443",
  "certificate": "cluster-node.crt",
  "private_key": "cluster-node.key",
  "ca_certificate": "cluster-ca.crt",
  "peers": ["https://203.0.113.11:8443", "https://203.0.113.12:8443"]
}
```

Chaque nœud répertorie tous les autres au moyen d’une URL HTTPS explicite comprenant une IP et un port. Limitez l’accès au port du cluster à ces nœuds. Utilisez une CA dédiée au cluster, ainsi qu’un certificat et une clé distincts pour chaque nœud. Le certificat doit contenir l’IP du nœud dans son SAN et autoriser l’authentification serveur et client. Les chemins sont relatifs au fichier JSON. Protégez les fichiers de la CA et de TLS, et conservez la clé privée de la CA hors ligne. L’authentification TLS mutuelle identifie les nœuds ; seules les valeurs TXT temporaires sont répliquées, jamais les certificats HTTPS, les clés privées ou la CA du mode local. Les variables d’environnement correspondantes sont `DNSBOX_NAMESERVERS` et `DNSBOX_CLUSTER_FILE`.

## Enregistrements ALIAS à l’apex de la zone

Pour faire pointer l’apex de la zone vers un nom d’hébergement externe, ajoutez ceci dans le fichier sélectionné par `--records-file` :

```text
apps.example.com ALIAS landing.example.net.
```

Configurez ce fournisseur d’hébergement pour qu’il serve votre domaine à l’apex et HTTPS. DNSBox résout la cible avant que le service DNS ne soit prêt, l’actualise en arrière-plan et répond à partir des enregistrements A/AAAA mis en cache, sans résolution pendant le traitement des requêtes. Si la résolution initiale échoue, le démarrage s’arrête ; un cache de plus d’une heure entraîne une réponse SERVFAIL aux requêtes A/AAAA. ALIAS n’est autorisé qu’à l’apex, doit cibler un nom extérieur à la zone et ne peut pas y coexister avec A, AAAA ou CNAME. NS, SOA, TXT, MX et les noms d’hôte du proxy basés sur une IP restent disponibles. Les listes statiques de serveurs de noms, la réplication des TXT en cluster et ALIAS nécessitent v0.5.2 ou une version ultérieure.

## Sécurité et compatibilité

Par défaut, seules les adresses publiques des serveurs applicatifs sont autorisées. Une liste explicite `--allowed-cidrs` limite l’accès aux réseaux indiqués et permet les déploiements privés. Pour un déploiement privé, liez les ports d’écoute aux interfaces du réseau local et protégez-les par votre pare-feu.

L’API d’administration écoute par défaut sur `127.0.0.1:8080`. Les modifications d’enregistrements nécessitent un jeton Bearer configuré ; une valeur vide `--api-listen=` désactive l’API. Les anciens points d’accès de partage de certificats sans authentification ont été supprimés. Chaque nœud conserve son propre magasin de certificats.

Les certificats et les clés privées sont conservés dans le répertoire de données. Sauvegardez ce répertoire de façon sécurisée. Les fichiers `certs/<hostname>.crt` et `.key` peuvent être utilisés par un autre service, tel qu’ocserv, mais le proxy inverse HTTP de DNSBox n’est pas un proxy OpenConnect/DTLS. Consultez les [instructions d’exportation des certificats](deployment.md#certificates-for-ocserv-or-another-service).

Lisez les [notes de migration vers v0.5](migration-v0.5.md) avant de mettre à niveau une installation v0.4.

## Développement

Utilisez la version de Go indiquée dans [go.mod](../go.mod).

```bash
go test -race ./...
go vet ./...
bash scripts/test-install.sh
go build ./cmd/dnsboxd
```

L’intégration continue de publication exécute les vérifications avant de publier les archives Linux, macOS et Windows pour amd64 et arm64. [Licence MIT](../LICENSE).