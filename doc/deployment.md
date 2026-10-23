# Deployment, private networks, and NAT

## How traffic flows

For `192-168-1-50.home.arpa`, DNSBox returns its configured `--ip`, e.g. `192.168.1.2`. A client connects to DNSBox over TLS. DNSBox extracts the backend address `192.168.1.50` from the hostname and forwards HTTP to it on `--upstream-port` (80 by default). The backend address and the proxy address are different roles.

A DNS A or AAAA answer must point to the TLS proxy for this model to work. DNSBox does not install software or keys on the backend. Merely resolving a hostname through a public DNS service does not add TLS support to your own server.

## Entirely private deployment

Use `--tls-mode=local` with a private zone such as `home.arpa`. Bind the listeners to the VM's LAN IP, advertise that LAN IP with `--ip`, and explicitly allow backend CIDRs.

```bash
./dnsboxd --domain=home.arpa --ip=192.168.1.2 \
  --tls-mode=local --allowed-cidrs=192.168.1.0/24 \
  --dns-listen=192.168.1.2:53 --https-listen=192.168.1.2:443 \
  --data-dir=/var/lib/dnsbox
```

Configure a conditional forwarder for `home.arpa` on your LAN resolver. A client can also use a hosts-file entry or `curl --resolve` for an individual hostname. Do not configure DNSBox as your sole general-purpose resolver: it is authoritative only for its zone.

No inbound Internet ports, router NAT rules, or outbound Internet access are needed in local mode. Allow LAN clients to reach the DNS and HTTPS listeners, and allow DNSBox to reach the backend's HTTP port.

The first local issuance creates `<data-dir>/ca/root.crt` and a private bundle `root.pem`. Keep `root.pem` private and back up the entire data directory. Copy only `root.crt` to clients through a trusted channel; installing it authorizes this CA to issue trusted certificates on those clients. Example commands:

```bash
# Debian/Ubuntu client:
sudo cp root.crt /usr/local/share/ca-certificates/dnsbox.crt
sudo update-ca-certificates

# macOS client:
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain root.crt
```

For Windows, import `root.crt` into the intended user's Trusted Root Certification Authorities store. Some browsers and applications use a separate trust store. Test trust explicitly; avoid disabling certificate verification.

To bootstrap the CA before serving clients, run your normal configuration with `--issue=192-168-1-50.home.arpa` once, then start the regular service. Local issuance opens no network listeners. Stop any DNSBox instance already using the same data directory before running the one-shot command.

## Private web services with a public certificate

Let's Encrypt DNS-01 validates **control of the hostname**, not public reachability of the backend web application. A private HTTP backend can therefore use a publicly trusted hostname if public DNS validation works. See [Let's Encrypt's DNS-01 documentation](https://letsencrypt.org/docs/challenge-types/#dns-01-challenge).

For the built-in single-instance ACME flow:

1. Use a domain or delegated subdomain you control, for example `apps.example.com`.
2. Delegate that zone to your nameserver; its public name must resolve to your router's public IP.
3. Forward public **UDP 53 and TCP 53** to the DNSBox VM. Keep both protocols enabled.
4. Run `--tls-mode=acme` and allow outbound HTTPS to the ACME service.
5. Allow private backends explicitly. Keep the HTTPS listener reachable only by the desired clients.

No incoming port 80 is required for DNS-01. Incoming 443 is required only for clients that need the proxy from outside your network.

`--ip` must be reachable by clients. When advertising a private proxy address while publishing public authoritative DNS, set up the nameserver's public address/glue at the parent and a matching custom address record for that nameserver. Confirm from outside the LAN that the delegation reaches the VM and TXT queries return its answers. Split DNS may also be needed for client routing. Do not assume NAT hairpinning is available.

This release does not synchronize challenge records among multiple independent DNSBox nodes and does not provide DNS zone transfers for secondary servers. Do not delegate to another DNS server unless it serves the same zone data and current ACME TXT values. The supported setup uses one DNSBox authoritative instance. If your registrar requires redundant nameservers, use a separate certificate client/provider or arrange external synchronization; pretending another independent instance is a secondary will cause intermittent validation failures.

For a genuinely offline network, public ACME validation is not possible. Use local mode and distribute trust instead.

## Certificates for ocserv or another service

DNSBox can write a hostname certificate and its private key for a service that terminates its own TLS. Its HTTP reverse proxy does not implement OpenConnect or DTLS.

With a zone you control and public DNS-01 validation configured, stop an existing DNSBox process using the same DNS address, then run:

```bash
./dnsboxd --domain=apps.example.com --ip=203.0.113.10 \
  --acme-email=admin@example.com --data-dir=/var/lib/dnsbox \
  --issue=198-51-100-20.apps.example.com
```

Replace the documentation addresses with real ones. The command opens DNS during issuance but does not bind HTTPS, so ocserv may keep port 443. It exits after writing:

- `/var/lib/dnsbox/certs/198-51-100-20.apps.example.com.crt` — PEM certificate chain.
- `/var/lib/dnsbox/certs/198-51-100-20.apps.example.com.key` — PEM private key.

Configure ocserv's `server-cert` and `server-key` with those files (or copies restricted to its service account), and make the VPN hostname resolve **directly to the ocserv server**. For DNSBox-served DNS, use an explicit custom A/AAAA record for that hostname. The hostname in the VPN client must match the certificate.

Arrange renewal by re-running the issuance command before expiry or running a persistent DNSBox instance with a separate HTTPS port; reload ocserv after the exported files change. A one-shot command cannot renew itself after it exits. Do not run a second process against a data directory already in use.

You cannot obtain another operator's private key through public DNSBox endpoints. The insecure legacy certificate-sharing API was removed.

## Without systemd

Use `bash install-dnsbox.sh ... --no-systemd`, then start `~/.dnsbox/run-dnsbox` under your init system or supervisor. On OpenRC/Calculate Linux, define a service that runs that launcher as the owner of the installation/data directories. Give it permission to bind low ports or use high ports with explicit forwarding.

On Linux, a dedicated service account and `CAP_NET_BIND_SERVICE` can avoid running as root. A manual [systemd unit](../systemd/dnsbox.service) is provided for installations using `/usr/local/bin/dnsboxd`, `/etc/dnsbox/dnsbox.env`, and `/var/lib/dnsbox`. Create those paths and the `dnsbox` account before enabling that template.

## Diagnosing issuance failures

- `No TXT record found`: check the authoritative delegation from outside your network, both DNS transports, the requested hostname/zone, and whether another nameserver answers without the challenge.
- The HTTPS request never reaches DNSBox: check that the hostname resolves to the advertised proxy IP and that the listener/firewall/NAT rules allow the client's connection.
- TLS succeeds but HTTP fails: check the backend CIDR policy, the HTTP port, and reachability from the DNSBox VM.
- Local TLS is untrusted: install the correct CA certificate on the client. A new data directory generates a different CA.
- Port already in use: bind to a specific unused interface or stop/reconfigure the conflicting service. DNSBox's installer does not disable your OS resolver.
