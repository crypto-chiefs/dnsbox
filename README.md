# 🧩 DNSBox

## ✅ Install

Run the install script with required flags:

```bash
bash <(curl -sSL https://raw.githubusercontent.com/crypto-chiefs/dnsbox/main/scripts/install.sh) --ip=YOUR_IP --domain=YOUR_DOMAIN
```

### Required flags

- `--ip` — your public IP address (example: `167.172.5.205`)
- `--domain` — your domain name that should point to this IP (example: `dnsbox.io`)
- `--ns` — subdomain name for your nameserver (example: `ns3` → full name will be `ns3.dnsbox.io`)
### Optional flags

- `--force-resolv` — disables `systemd-resolved` and sets `/etc/resolv.conf` to `nameserver 8.8.8.8`  
  Use this if port `53` is already occupied.

---

### Full example:

```bash
bash <(curl -sSL https://raw.githubusercontent.com/crypto-chiefs/dnsbox/main/scripts/install.sh) --ip=167.172.5.205 --domain=dnsbox.io --ns=ns3 --force-resolv
```

---

## ❌ Uninstall

To completely remove DNSBox from your system:

```bash
bash <(curl -sSL https://raw.githubusercontent.com/crypto-chiefs/dnsbox/main/scripts/uninstall.sh)
```

This will:

- Stop and disable the `dnsbox` systemd service (if running)
- Remove the systemd unit file
- Delete the DNSBox binary and working directory (`~/.dnsbox`)
