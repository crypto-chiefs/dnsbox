# DNSBox

DNSBox associe un serveur DNS faisant autorité à un proxy inverse HTTPS. Les noms comme `192-168-1-50.home.arpa` encodent l’IP du serveur applicatif ; le DNS pointe vers le proxy DNSBox.

- `--tls-mode=local` : réseau privé sans Internet ni redirection de ports. Les clients doivent faire confiance à l’autorité de certification locale.
- `--tls-mode=acme` : certificats pour les noms d’une zone DNS que vous contrôlez ; DNS public sur UDP et TCP 53 requis. DNS-01 ne nécessite pas le port entrant 80.
- Les serveurs privés nécessitent une liste explicite `--allowed-cidrs`.
- Le certificat porte sur le nom DNS, pas sur l’adresse IP seule. Installer DNSBox ne donne pas le contrôle de `dnsbox.io`.

Les anciennes instructions ont été remplacées pour v0.5. La documentation complète et à jour est disponible en anglais :

[Guide](../README.md) · [Réseaux privés et NAT](deployment.md) · [Configuration](configuration.md) · [Migration](migration-v0.5.md)