# DNSBox — किसी भी IP पते के लिए HTTPS और Let's Encrypt

[🇬🇧 English](../README.md) | [🇷🇺 Русский](/doc/README.ru.md) | [🇪🇸 Español](/doc/README.es.md) | [🇩🇪 Deutsch](/doc/README.de.md) | [🇫🇷 Français](/doc/README.fr.md) | [🇨🇳 中文](/doc/README.zh.md) | [🇮🇳 हिंदी](/doc/README.hi.md) | [🇧🇷 Português](/doc/README.pt.md) | [🇹🇷 Türkçe](/doc/README.tr.md) | [🇮🇩 Bahasa Indonesia](/doc/README.id.md) | [🇻🇳 Tiếng Việt](/doc/README.vi.md) | [🇰🇷 한국어](/doc/README.ko.md)

[![Release](https://img.shields.io/github/v/release/crypto-chiefs/dnsbox)](https://github.com/crypto-chiefs/dnsbox/releases)
[![Go Version](https://img.shields.io/github/go-mod/go-version/crypto-chiefs/dnsbox)](../go.mod)

**DNSBox** एक ओपन-सोर्स DNS सर्वर है जो किसी भी सार्वजनिक IP पते (IPv4 और IPv6) के लिए मुफ्त SSL प्रमाणपत्र (Let's Encrypt) जारी करने की अनुमति देता है, बिना किसी डोमेन के। अपने सर्वर, API या IoT डिवाइस तक HTTPS के माध्यम से सीधे IP के माध्यम से पहुँच प्राप्त करें।

---

## 🔍 विशेषताएं

- 🔐 **Let's Encrypt से मुफ्त SSL प्रमाणपत्र**
- 🌐 **IPv4 और IPv6 का समर्थन करता है**
- ⚡ **बिना DNS कॉन्फ़िगरेशन के तत्काल HTTPS एक्सेस**
- 🔄 **स्वचालित प्रमाणपत्र नवीनीकरण**
- 💡 **बिना डोमेन के भी कार्य करता है** — `*.dnsbox.io` उपडोमेन का उपयोग करें
- 🧩 **WebSocket, API और CI/CD परिदृश्यों के साथ संगत**
- ⚙️ **शेल स्क्रिप्ट के माध्यम से आसान इंस्टॉलर**
- 📦 न्यूनतम निर्भरता, एकल बाइनरी, शून्य-कॉन्फ़िगरेशन शुरू

---

## 📦 इंस्टॉलेशन

```bash
bash <(curl -sSL https://raw.githubusercontent.com/crypto-chiefs/dnsbox/main/scripts/install.sh) --ip=167.172.5.205 --domain=dnsbox.io --ns=ns3
```

पैरामीटर:
- `--ip` — आपका सार्वजनिक IP पता (अनिवार्य)
- `--domain` — NS से जुड़ा मूल डोमेन (जैसे `dnsbox.io`)
- `--ns` — नेमसर्वर का उपडोमेन (जैसे `ns3`)
- `--force-resolv` — systemd-resolved को अक्षम करता है और 8.8.8.8 सेट करता है
- `--debug` — विस्तृत मोड सक्षम करता है

---

## 🌐 यह कैसे काम करता है

1. DNSBox एक नेमसर्वर शुरू करता है जो गतिशील रूप से A/AAAA और TXT रिकॉर्ड प्रदान करता है।
2. आपको एक उपडोमेन प्राप्त होता है जैसे `167.172.5.205.dnsbox.io`।
3. Let's Encrypt `_acme-challenge` TXT रिकॉर्ड को सत्यापित करता है और प्रमाणपत्र जारी करता है।
4. DNSBox स्वचालित रूप से प्रमाणपत्र सहेजता है, नवीनीकृत करता है और परोसता है।

---

## 🛠 उपयोग उदाहरण

इंस्टॉलेशन के बाद, आप HTTPS के माध्यम से अपने सर्वर से कनेक्ट कर सकते हैं:

```bash
curl https://167.172.5.205.dnsbox.io
```

या OpenSSL के माध्यम से SSL परीक्षण करें:

```bash
openssl s_client -connect 167.172.5.205:443 -servername 167.172.5.205.dnsbox.io
```

---

## ⚙️ तकनीकी विवरण

- भाषा: Go
- DNS लाइब्रेरी: [miekg/dns](https://github.com/miekg/dns)
- TLS: मानक `crypto/tls`
- ACME क्लाइंट: अंतर्निहित समर्थन (certbot की आवश्यकता नहीं)
- इन-मेमोरी लॉजिक: सभी DNS अनुरोध और चैलेंज स्मृति में संभाले जाते हैं

---

## 🧪 उपयोग के मामले

- 🔧 बिना डोमेन के DevOps बुनियादी ढांचा
- 📡 सार्वजनिक IP वाले IoT डिवाइस
- 🧪 परीक्षण और स्टेजिंग वातावरण
- 🚀 बिना DNS कॉन्फ़िगरेशन के तेज़ API परिनियोजन
- 🔐 HTTPS की आवश्यकता वाले VPN/प्रॉक्सी सेवाएँ

---

## 🔒 सुरक्षा

Let's Encrypt के सभी चैलेंज अनुरोध केवल मान्य IP सत्यापन के दौरान ही प्रदान किए जाते हैं। TLS निजी कुंजियाँ `/var/lib/dnsbox/certs` में सहेजी जाती हैं।

---

## 🗺 sslip.io और nip.io का विकल्प

मौजूदा सेवाओं के विपरीत:
- DNSBox एक **स्व-होस्टेड ओपन-सोर्स समाधान** है
- आप अपना स्वयं का `*.yourdomain.tld` तैनात कर सकते हैं
- **IPv6**, ACME और **बिना किसी तीसरे पक्ष की API के** प्रमाणपत्र का समर्थन करता है

---

## 📜 लाइसेंस

यह प्रोजेक्ट MIT लाइसेंस के तहत लाइसेंस प्राप्त है। स्वतंत्र रूप से उपयोग करें, फोर्क करें और विस्तारित करें।

---

## 🔗 सहायक लिंक

- 🌍 वेबसाइट: https://dnsbox.io/
- 📦 इंस्टॉलर: [install.sh](https://github.com/crypto-chiefs/dnsbox/blob/main/scripts/install.sh)
- 📖 दस्तावेज़: निर्माणाधीन

---

⭐ यदि आपको यह प्रोजेक्ट उपयोगी लगे, तो कृपया GitHub पर इसे ⭐ दें!
