# DNSBox

DNSBox एक authoritative DNS सर्वर और HTTPS reverse proxy को जोड़ता है। `192-168-1-50.home.arpa` जैसे नाम backend का IP दर्शाते हैं; DNS उत्तर DNSBox proxy के पते पर जाता है।

- `--tls-mode=local`: निजी नेटवर्क के लिए, बिना इंटरनेट या port forwarding के। क्लाइंट को स्थानीय CA पर भरोसा करना होगा।
- `--tls-mode=acme`: आपके नियंत्रण वाले DNS zone के नामों के लिए प्रमाणपत्र। सार्वजनिक UDP और TCP 53 DNS आवश्यक है; DNS-01 के लिए incoming port 80 आवश्यक नहीं है।
- निजी backends के लिए स्पष्ट `--allowed-cidrs` सूची आवश्यक है।
- प्रमाणपत्र DNS नाम के लिए है, केवल IP पते के लिए नहीं। स्थापना से `dnsbox.io` का नियंत्रण नहीं मिलता।

पुराने स्थापना निर्देश v0.5 के लिए बदल दिए गए हैं। पूर्ण और अद्यतन दस्तावेज़ अंग्रेज़ी में उपलब्ध हैं:

[मार्गदर्शिका](../README.md) · [निजी नेटवर्क और NAT](deployment.md) · [कॉन्फ़िगरेशन](configuration.md) · [माइग्रेशन](migration-v0.5.md)